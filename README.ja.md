# protobuf.interceptors

最終更新: 2026-10-01

[![CI](https://github.com/o3co/protobuf.interceptors/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/protobuf.interceptors/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/o3co/protobuf.interceptors/graph/badge.svg)](https://codecov.io/gh/o3co/protobuf.interceptors)
[![Go Reference](https://pkg.go.dev/badge/github.com/o3co/protobuf.interceptors.svg)](https://pkg.go.dev/github.com/o3co/protobuf.interceptors)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> このリポジトリは、[auth](https://github.com/o3co/auth) スタックの 3 層責務分離（[認証・トークン発行](https://github.com/o3co/auth.provider) / [認可判定](https://github.com/o3co/auth.policy-verifier) / 認可実施）のうち、**認可実施**（gRPC / ConnectRPC）を担う。allow / deny の判定は auth.policy-verifier、OPA、Cedar、またはその他の `VerifierEndpoint` に委ねる。

Go 向けの、フレームワーク非依存な protobuf メソッドオプション認可インターセプター。アクセスポリシー（リソース + アクション）を `.proto` のメソッドオプションで宣言し、差し替え可能な検証バックエンドを通して実行時に実施する。gRPC と ConnectRPC の両方に対応する。

## 責務と役割

**役割。** このライブラリは auth スタックの実施層であり、Go サービスの内部、その gRPC または ConnectRPC ハンドラーの前段に置く。認証とトークン発行は [auth.provider](https://github.com/o3co/auth.provider) が、認可判定はバックエンド — [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier)、OPA、Cedar エージェント、または独自の `VerifierEndpoint` — が担う。このライブラリはバックエンドに問い合わせ、その答えを実施する。

**担うもの:**

- メソッドが `.proto` のオプションで宣言したポリシーを読み、リクエストからリソースとアクションを解決すること。指すリソースを変えてしまうリクエストの値は拒否する
- リクエストから Bearer トークンとリクエスト ID を読み、不正な形のクレデンシャルを拒否し、両方をバックエンドに渡すこと
- ハンドラーの実行前に — ストリームでは受信する各メッセージについても — バックエンドに問い合わせ、許可されない限り RPC を拒否すること
- 結果を、固定メッセージ付きのステータスコードとして呼び出し元に伝え、完全なエラーとその背後の判定をサービスに渡すこと
- 組み込みバックエンド用の HTTP クライアント: 平文はループバックにのみ送り、リダイレクトに追従せず、読み取り量を制限し、各バックエンドの答えを厳密に読む

**担わないもの:**

- **認証。** 確認するのは `authorization` の値の形だけで、トークンの署名・有効期限・issuer・audience は一切検証しない。それはバックエンドの役目（o3co と OPA のエンドポイントはトークンをバックエンドに送る）か、Cedar では利用者が与える principal リゾルバーの役目である。
- **判定。** ここではポリシーを評価しない。static エンドポイントは、利用者が与えたリソースとアクションのパターンの固定リストを照合するだけである。
- **記録。** インターセプターは自らはログを書かない。判定はハンドラーとオブザーバーに渡る（[判定の記録](#判定の記録)を参照）。
- サーバー自身のトランスポートの保護や、リクエストレートの制限。

フレームワーク別のインターセプターを別モジュールにしているのは、gRPC サービスが ConnectRPC に、ConnectRPC サービスが grpc-go に依存しないようにするためである（[モジュール](#モジュール)を参照）。

## 仕組み

認可ポリシーを `.proto` ファイルに直接定義する:

```proto
import "policy.proto";

service PostService {
  rpc GetPost(GetPostRequest) returns (Post) {
    option (o3co.authz.v1.policy) = {
      resource: "posts/<id>"
      action: "read"
      field_mappings: [{ placeholder: "id", request_field: "id" }]
    };
  }

  rpc CreatePost(CreatePostRequest) returns (Post) {
    option (o3co.authz.v1.policy) = {
      resource: "posts"
      action: "write"
    };
  }

  // No policy option = no authorization check
  rpc HealthCheck(Empty) returns (Status);
}
```

実行時、インターセプターはオプションを読み、リクエストからフィールドマッピングを解決し、検証バックエンドを呼び出す:

```text
RPC request
     │
     ▼
┌──────────────────────────────────┐
│  PolicyOptionInterceptor         │  reads (o3co.authz.v1.policy) from proto,
│                                  │  resolves <placeholder> from request fields,
│                                  │  stores PolicyData{Resource, Action} in ctx
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  VerificationInterceptor         │  reads policy from ctx,
│                                  │  calls VerifierEndpoint.Verify(),
│                                  │  refuses with PermissionDenied,
│                                  │  Unauthenticated or Internal
└───────────────┬──────────────────┘
                │
                ▼
          handler (your code)
```

### どのメソッドが検査されるか

ポリシーは protobuf レジストリにあるメソッドのディスクリプターから読む:

- **ディスクリプターがあり、ポリシーオプションが設定されている** — RPC は検査される。
- **ディスクリプターがあり、ポリシーオプションが無い** — RPC は検査されずに通過する。grpc-go では、ヘルスサービスとリフレクションサービス（`google.golang.org/grpc/health`、`google.golang.org/grpc/reflection`）がこれにあたる。
- **ディスクリプターが無い** — ポリシーが分からないので、RPC はハンドラーの実行前に `Internal` で**拒否**される。gRPC では `protoregistry.GlobalFiles` に無いメソッドがこれにあたる: `grpc.UnknownServiceHandler` が扱うもの、`.proto` が登録されていない手書きの `ServiceDesc` が扱うもの、そしてディスクリプターが `GlobalFiles` ではなく gogo のレジストリに登録される gogo/protobuf 生成のサービス。ConnectRPC では `connect.WithSchema` なしで作ったハンドラーがこれにあたる: 手組みのハンドラー、`connect.WithSchema` を出力しない古い protoc-gen-connect-go のコード、そしてスキーマを設定しない ConnectRPC 自身の `connectrpc.com/grpchealth` と `connectrpc.com/grpcreflect` のハンドラー。これらはインターセプターなしでマウントすること（[ConnectRPC](#connectrpc)を参照）。

サーバーリフレクションはメソッドオプションを公開するので、リフレクションサービスに到達できるクライアントは、すべてのメソッドのポリシーオプション — リソーステンプレート、アクション、フィールドマッピング — を読める。

### プレースホルダーの値

`<placeholder>` は呼び出し元が制御するリクエストフィールドから埋められ、その結果は認可バックエンドが解析する。したがって値に許されるのは、リソース文字列の一部を埋めることだけであり、その構造を変えることは決して許されない。

解決処理は、値のすべての文字が [auth.policy-verifier] のドット記法文法のセグメントトークンに含まれない限り、その値を拒否する: **スペース、`"`、`\`、`.`、`:` を除く印字可能 ASCII**。空の値も拒否する。テンプレートの構成要素を埋めるのではなく消してしまうからである。`/`、`-`、`_`、`%` とその他の印字可能 ASCII は問題ない。

`.` と `:` は構造を表す文字である: `.` はリソース型を構成するセグメントを区切り、`:` は型と id を区切る。拒否が無ければ、`resource: "posts:<id>"` を宣言したポリシーと、id フィールドに `1.member:2` を持つリクエストは `posts:1.member:2` に解決され、verifier はそれをリソース型 `posts.member` と読む — RPC が守っていなかった型について判定が下され、本来その RPC を通すか決めるはずのルールは実行されない。

すべてのバックエンド（o3co、OPA、Cedar、static ルール）は同じ解決済み文字列を使うので、拒否はバックエンドを呼ぶ前、解決の段階で起こる。これは `*interceptors.ResourceValueError` として現れ、gRPC と ConnectRPC のインターセプターはそれを固定メッセージ `access denied` 付きの `PermissionDenied` に変換する — リクエストは拒否され、ハンドラーは実行されず、verifier には問い合わせない。どのプレースホルダーのどの文字が拒否されたかは呼び出し元に送らない。それを読める場所は[エラー](#エラー)を参照。

**id が正当に `.`、`:`、非 ASCII を含む場合** — DID、メールアドレス、ドット区切りのバージョン、非ラテン文字の id — リクエストは拒否される。どのフレームワークでも使える対処が 3 つあり、どれが合うかはバックエンドによる:

- **値がマッピング先のリクエストフィールドに入る前にパーセントエンコードする。** パーセントエンコードは文法を往復しても崩れず（`1%2Emember` は 1 つのセグメントのまま）、`%` 自体も受け付けられるので、verifier は元に戻せる。他のバックエンドでは、エンコード後の形に対してポリシーを書く。
- **id の構文に合わせて書いた `ResourceParser` を verifier に設定し**、呼び出し側でその構文にエンコードする。これには auth.policy-verifier（o3co エンドポイント）が必要である。
- **問題の値がリソースに代入されないようにポリシーを組み替える。** リソース文字列で DID を名指しする代わりに、RPC が実際に持つ型を守り（`resource: "subscriptions"`、`action: "read"`）、Bearer トークンからすでに持っているアイデンティティに対してバックエンドに判定させる。verifier、OPA、Cedar はトークンを見られるが、static エンドポイントはリソースとアクションしか照合しないので、この判定はできない。

4 つ目の道 — フィールドマッピングは残し、そのプレースホルダーをリソーステンプレートから外して、値をリクエストコンテキストとして運ぶ — は**移植性が無い**: ConnectRPC と o3co エンドポイントの組み合わせでしか機能しない。頼る前に[抽出フィールドの転送](#抽出フィールドの転送)を読むこと。

代入はテンプレートに対する 1 回の走査である: それ自体が `<some-placeholder>` と綴られた値はデータのまま残り、別のマッピングによって書き換えられることはない。

テンプレート中のすべての `<name>` にはフィールドマッピングが必要である。マッピングが無いもの — 綴りを誤ったプレースホルダーや、テンプレートに残したままマッピングだけ消したもの — は、どのポリシーも意図しないリソースを指すリテラル文字列としてバックエンドに届くのではなく、`Internal` で解決に失敗する。

### プレースホルダーが読めるリクエストフィールド

`request_field` はリクエストメッセージの**トップレベル**のフィールドを `.proto` のフィールド名で指す。ネストしたメッセージへのドット区切りのパスは読まない。フィールドは次のいずれかの種類の単一値（`repeated` でも `map` でもない）でなければならない:

| 種類 | 代入される形 |
|---|---|
| `string` | 値そのまま |
| `int32`、`sint32`、`sfixed32`、`int64`、`sint64`、`sfixed64` | 10 進数。負なら `-` 付き |
| `uint32`、`uint64`、`fixed32`、`fixed64` | 10 進数 |
| `bool` | `true` または `false` |
| `bytes` | 小文字の 16 進数 |

それ以外の種類 — `enum`、`float`、`double`、メッセージ — と、メッセージに無いフィールドは `Internal` で解決に失敗する。リクエストが設定しなかったフィールドはデフォルト値（proto3 ではゼロ値）に解決される: `0` と `false` はプレースホルダーを埋めるが、空の `string` と `bytes` は空として拒否される。

`bytes` フィールドは常に小文字の 16 進エンコードとして代入される: バイト `0xff` は `ff` に、2 バイトの `"ff"` は `6666` に解決されるので、異なる 2 つの値が同じリソースを指すことはない。

### 抽出フィールドの転送

`ResolveResourceWithFields` は、プレースホルダーがリソーステンプレートに現れないものも含め、**すべての** `field_mappings` エントリを抽出する。そうした値は代入されないので、上のセグメント文法は適用されない — すべてコロンでできた DID も問題なく抽出される。それが認可判定に届くかどうかは、フレームワーク*と*バックエンドの両方による:

| 経路 | 抽出される | コンテキストに置かれる | 判定に届く |
|---|---|---|---|
| ConnectRPC unary | はい | はい | **o3co** エンドポイント経由でのみ |
| ConnectRPC streaming | — | — | いいえ — `field_mappings` は `Internal` で拒否 |
| gRPC unary | はい | **いいえ、破棄される** | **いいえ** |
| gRPC streaming | — | — | いいえ — `field_mappings` は `Internal` で拒否 |

`ResolveResourceWithFields` で解決し、その結果を `interceptors.WithExtractedFields` で付けるのは `connectrpc.PolicyOptionInterceptor` だけである。gRPC の unary インターセプターはフィールドを捨てる `ResolveResource` で解決し、両方のストリームインターセプターは `field_mappings` を持つポリシーを何も解決する前に拒否する（[ストリーミング](#ストリーミング)を参照）。そして 4 つのバックエンドのうち、コンテキストを読み出すのは `endpoint.NewO3coEndpoint` だけで、それを `POST /verify` の `context` オブジェクトとして送る — OPA、Cedar、static エンドポイントは見ない。

**したがって gRPC unary では、プレースホルダーをリソーステンプレートから外しても、その値が判定に使えるようにはならない — 値が消えるだけである**: 解決はもう値を拒否しないが、verifier はその値なしで判定する。以前より情報の少ない問いであり、拒否よりも悪い。（ポリシーにマッピングを残した gRPC ストリームは引き続き `Internal` で失敗する。[ストリーミング](#ストリーミング)を参照。）バックエンドが対応する上記の対処のいずれかを使うこと。

gRPC unary の経路は、ConnectRPC のように値を転送しない。ストリームインターセプターが `field_mappings` を拒否するのは、どちらのフレームワークでも別個の制限である: ポリシーインターセプターはハンドラーがリクエストメッセージを読む前に動き、クライアントストリームや双方向ストリームには単一のリクエストメッセージが無い。

[auth.policy-verifier]: https://github.com/o3co/auth.policy-verifier

## モジュール

3 つの Go モジュールがあり、それぞれ独立にバージョン付けされリリースされる（[バージョンとリリース](#バージョンとリリース)を参照）:

| モジュール | インポートパス | ビルドでコンパイルされるもの |
|---|---|---|
| コア | `github.com/o3co/protobuf.interceptors` | `google.golang.org/protobuf` + 標準ライブラリ |
| gRPC | `github.com/o3co/protobuf.interceptors/grpc` | コア + `google.golang.org/grpc` |
| ConnectRPC | `github.com/o3co/protobuf.interceptors/connectrpc` | コア + `connectrpc.com/connect` |

コアモジュールには proto スキーマ、コンテキストヘルパー、エラー型、リソース解決、すべての検証バックエンドが含まれる。フレームワーク別のモジュールはインターセプターの実装だけを提供する。

コアの `go.mod` は `google.golang.org/grpc` と `connectrpc.com/connect` も require している: コア自身のテストと両フレームワークモジュールのテストが共有する `testproto/` 配下のテストサービスが、コアモジュールに含まれるからである。他のコアパッケージはどちらも import しないので、これらは利用者のモジュールグラフには加わるが、import しない限りコンパイルされない。

## インストール

```bash
# gRPC users
go get github.com/o3co/protobuf.interceptors/grpc

# ConnectRPC users
go get github.com/o3co/protobuf.interceptors/connectrpc
```

## 使い方

### gRPC

```go
import (
    policygrpc "github.com/o3co/protobuf.interceptors/grpc"
    "github.com/o3co/protobuf.interceptors/endpoint"
)

// Create a verification backend
verifier, _ := endpoint.NewOPAEndpoint("http://localhost:8181", "authz/allow")

// Chain interceptors
srv := grpc.NewServer(
    grpc.ChainUnaryInterceptor(
        policygrpc.PolicyOptionInterceptor(),
        policygrpc.VerificationInterceptor(verifier),
    ),
    grpc.ChainStreamInterceptor(
        policygrpc.PolicyOptionStreamInterceptor(),
        policygrpc.VerificationStreamInterceptor(verifier),
    ),
)
```

### ConnectRPC

```go
import (
    policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
    "github.com/o3co/protobuf.interceptors/endpoint"
)

// The Cedar agent authenticates nothing: the resolver verifies the bearer
// token and names the principal it stands for.
verifier, _ := endpoint.NewCedarEndpoint("http://localhost:8180",
    endpoint.WithCedarPrincipalResolver(func(ctx context.Context, token string) (string, error) {
        claims, err := verifyJWT(ctx, token) // signature, expiry, issuer, audience
        if err != nil {
            return "", err
        }
        return claims.Subject, nil
    }),
)

mux := http.NewServeMux()
path, handler := foopbconnect.NewFooServiceHandler(
    &fooServer{},
    connect.WithInterceptors(
        policyconnect.PolicyOptionInterceptor(),
        policyconnect.VerificationInterceptor(verifier),
    ),
)
mux.Handle(path, handler)
```

`connectrpc.com/grpchealth` と `connectrpc.com/grpcreflect` はハンドラーを `connect.WithSchema` なしで作るので、これらのインターセプターの後ろでは、すべてのヘルスチェックとリフレクションのリクエストが `Internal` で拒否される。インターセプターは、すべてのハンドラーで共有する 1 つのオプションとしてではなく、自分のサービスのハンドラーにだけ渡すこと:

```go
// The service is checked.
mux.Handle(foopbconnect.NewFooServiceHandler(&fooServer{},
    connect.WithInterceptors(
        policyconnect.PolicyOptionInterceptor(),
        policyconnect.VerificationInterceptor(verifier),
    ),
))

// Health and reflection are mounted without the interceptors.
mux.Handle(grpchealth.NewHandler(grpchealth.NewStaticChecker(foopbconnect.FooServiceName)))
reflector := grpcreflect.NewStaticReflector(foopbconnect.FooServiceName)
mux.Handle(grpcreflect.NewHandlerV1(reflector))
mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
```

インターセプターが守るのはハンドラーである。ConnectRPC のクライアントに渡した場合、どちらもすべての呼び出しをそのまま通す。

### Bearer トークンとリクエスト ID

検証インターセプターは両方をリクエスト（gRPC メタデータまたは HTTP ヘッダー）から読み、エンドポイントを呼ぶコンテキストに置く:

- **Bearer トークン** — `authorization` から。何も持たないリクエストにはトークンが無く、それを通してよいかはバックエンドの判定である。`endpoint` パッケージのエンドポイントはどれも、バックエンドに問い合わせずに `UnauthenticatedError` として拒否する。それ以外の場合、リクエストは `Bearer <token>` 形式の値をちょうど 1 つ持たなければならない: スキームは大文字小文字を区別せずに比較し（RFC 9110 §11.1）、トークンは空でなく、Unicode の空白を含まないこと（RFC 6750 の `b64token` は空白を含まない）。複数の値、別のスキーム、空のトークンは、どのバックエンドにも問い合わせる前に `Unauthenticated` で拒否され、オブザーバーはその拒否を見る。ポリシーの無いメソッドは検査されない: 正しい形のトークンはそのコンテキストに置かれるが、不正な形のクレデンシャルは拒否されない。
- **リクエスト ID** — `x-request-id` から。送られた 1 つの値が `A-Z a-z 0-9 - _ . : + / = #` の 1〜128 文字 — auth.policy-verifier が受け付ける形 — であれば、それを保持する。それ以外 — 無い、複数ある、その形から外れる — の場合、インターセプターは `YYYYMMDDHHmmss_<16 桁の 16 進数>`（UTC の秒と 8 バイトの乱数）を生成する。両フレームワークとも、`interceptors.InboundBearerToken` と `interceptors.InboundRequestID` を通して同じことをする。

### エラー

呼び出し元には、結果がステータスコードと固定メッセージで伝えられ、両フレームワークで同じである。エンドポイントのエラーはバックエンド、呼び出した URL、トークンを拒否した理由を含みうるので、そのテキストは呼び出し元に一切届かない:

| 原因 | コード | メッセージ |
|---|---|---|
| `*interceptors.DeniedError`（拒否されたプレースホルダーの値を含む） | `PermissionDenied` | `access denied` |
| `*interceptors.UnauthenticatedError`（読み取れないクレデンシャルを含む） | `Unauthenticated` | `unauthenticated` |
| RPC 自身のコンテキストがキャンセルされたときの `context.Canceled` | `Canceled` | `request canceled` |
| RPC 自身のデッドラインが過ぎたときの `context.DeadlineExceeded` | `DeadlineExceeded` | `deadline exceeded` |
| それ以外すべて — バックエンドの失敗（RPC が生きている間にエンドポイント自身の HTTP タイムアウトが発火した場合を含む）、ディスクリプターの無いメソッド、マッピングの無いプレースホルダー、ストリームの `field_mappings`、順序の誤ったインターセプターチェーン、`UnconfirmedRevisionError`、`ErrCallerUnauthenticated` | `Internal` | `authorization check failed` |

完全なエラーは、すべての検査について `WithDecisionObserver` のオブザーバーに渡る（[判定の記録](#判定の記録)を参照）。インターセプターが返すエラーもそれに unwrap できるので、これらより外側に置いたインターセプターは `errors.As` / `errors.Is` で取り出せる — オブザーバーが見ないポリシー参照や解決の失敗は、そこでログできる。インターセプターは自らはログを書かない。

## 検証バックエンド

`endpoint` パッケージは 4 つのバックエンドを提供する:

| バックエンド | コンストラクター | プロトコル |
|---|---|---|
| OPA | `endpoint.NewOPAEndpoint(baseURL, policyPath)` | `POST /v1/data/{path}` |
| Cedar Agent | `endpoint.NewCedarEndpoint(baseURL, endpoint.WithCedarPrincipalResolver(fn))` | `POST /v1/is_authorized` |
| o3co policy-verifier | `endpoint.NewO3coEndpoint(baseURL)` | `POST /verify` |
| Static rules | `endpoint.NewStaticEndpoint(rules)` | ローカルで評価 |

**Cedar エンドポイントは認証をしない。** Cedar エージェントは問われた principal について何であれ判定し、Bearer トークンは見せられないので、`NewCedarEndpoint` は `WithCedarPrincipalResolver` を必須とする: トークンを検証し — JWT なら署名、有効期限、issuer、audience — principal の id を返す関数である。トークンをデコードするだけのリゾルバーでは、どの呼び出し元もどの principal でも名乗れてしまう。エラーまたは空の id は `UnauthenticatedError` になり、エージェントには問い合わせない。id は Cedar の文字列リテラルとしてエスケープされるので、引用符やバックスラッシュが含まれても、指すエンティティは変わらない。

ベース URL はスキーム（`http` または `https`）とホストを指定する。どちらかを欠くものは、推測されずに構築時に拒否される。o3co や OPA へのリクエストはサブジェクトの Bearer トークンを、Cedar へのリクエストはそこから解決した principal を運ぶので、`http://` はループバック — `localhost`、`127.0.0.0/8`、`::1` — にのみ許される。ただしエンドポイントに `WithO3coAllowInsecure()`、`WithOPAAllowInsecure()`、`WithCedarAllowInsecure()` を与えた場合は別である。それ以外では `https://` を使うこと。`localhost` は大文字小文字を問わず名前で受け付け、他のホストと同じく `/etc/hosts` と DNS で解決される。リテラルのアドレスは 127.0.0.0/8 内のもの、または `::1`（IPv4 射影の `::ffff:127.x.y.z` を含む）として書かれた場合にのみ受け付けるので、`localhost.`、`foo.localhost`、`127.1`、`2130706433`、`0.0.0.0`、ゾーン付きの `::1%lo0` はループバックではない。

どの HTTP バックエンドもリダイレクトに追従しない: `3xx` はエラーであり、リクエストとそれに載る Bearer トークンは設定したバックエンドにしか届かない。

呼び出し元のコンテキストがキャンセルされるかデッドラインが過ぎると、HTTP エンドポイントのエラーは `ctx.Err()` をラップするので、`errors.Is` で `context.Canceled` または `context.DeadlineExceeded` が見つかる。エンドポイント自身のタイムアウトはバックエンドが答えなかったということであり、どちらもラップしない。

相互 TLS やプライベート CA には、送信に使うトランスポートをエンドポイントに与える — `WithO3coTransport(rt)`、`WithOPATransport(rt)`、`WithCedarTransport(rt)`。たとえば `TLSClientConfig` を設定した `*http.Transport` である。エンドポイントのタイムアウトとリダイレクト不追従は、`*http.Transport` のように、リクエストのコンテキストを尊重し、自らリダイレクトに追従しないトランスポートであれば引き続き適用される。

```go
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.TLSClientConfig = &tls.Config{
    RootCAs:      privateCAs,
    Certificates: []tls.Certificate{clientCert},
}
verifier, err := endpoint.NewO3coEndpoint(
    "https://verifier.internal:3000",
    endpoint.WithO3coTransport(transport),
)
```

### o3co エンドポイントのオプション

| オプション | 効果 |
|---|---|
| `WithO3coTimeout(d)` | HTTP クライアントのタイムアウト。デフォルト `10s`。`d` が正でなければ panic する。 |
| `WithO3coMaxResponseBodySize(n)` | レスポンスボディから読むバイト数の上限。デフォルト 1 MiB。`n` が正でなければ panic する。 |
| `WithO3coLogLevel(level)` | エンドポイント内部のロガーのレベル。デフォルト `slog.LevelError`。 |
| `WithO3coRequestIDHeaderKey(key)` | リクエスト ID を転送するヘッダー。デフォルト `x-request-id`。`""` で転送しない。`key` が `Authorization`、`Content-Type`、`Accept` 以外の RFC 7230 トークンでなければ panic する。`WithO3coHeaders` のヘッダーも同じキーを指すと `NewO3coEndpoint` がエラーを返す。OPA と Cedar のオプションも同じ検査をする。 |
| `WithO3coHeaders(map[string]string)` | すべての verify リクエストに加える静的ヘッダー。複数回の呼び出しはマージされる。 |
| `WithO3coRequireConfirmedRevision()` | 確認済みのポリシーリビジョンに基づくと確定できない allow を拒否する。デフォルトはオフ。[確認済みリビジョンの要求](#確認済みリビジョンの要求)を参照。 |
| `WithO3coAllowInsecure()` | ループバック以外のホストへの `http://` ベース URL を許可する。 |
| `WithO3coTransport(rt)` | リクエストを送るトランスポート。相互 TLS など。デフォルト `http.DefaultTransport`。`rt` が nil なら panic する。 |

`WithO3coHeaders` は、auth.policy-verifier の任意の `http.callerAuth` ゲートを有効にしたデプロイで必要になる。このゲートは専用のヘッダー（デフォルト `x-caller-token`）で共有クレデンシャルを期待し、サブジェクトの Bearer トークンとは別の問い — *どのサービスが*そもそも判定を求めてよいか — に答える。それを送る手段が無ければ、ゲートを有効にした時点で、すべての Go の実施ポイントが `401 caller_unauthenticated` で拒否される。

```go
verifier, err := endpoint.NewO3coEndpoint(
    "http://localhost:3000",
    endpoint.WithO3coHeaders(map[string]string{
        "x-caller-token": os.Getenv("VERIFIER_CALLER_TOKEN"),
    }),
)
```

エンドポイント自身が設定するヘッダー — `Content-Type`、`Accept`、`Authorization`、設定したリクエスト ID ヘッダー — はここで上書きできない。`NewO3coEndpoint` は、静的ヘッダーが黙ってサブジェクトトークンを置き換えることを許さず、エラーを返す。（リクエスト ID の転送を無効にすると、エンドポイントはそのヘッダーを設定しなくなるので、それは解放される。）

verifier は、不正なサブジェクトトークンにも、拒否した呼び出し元クレデンシャルにも `401` で答える。エンドポイントはレスポンスの `code` で両者を区別する: `caller_unauthenticated` による拒否は `endpoint.ErrCallerUnauthenticated` を返し、インターセプターはそれを `Internal` に変換する — 呼び出し元トークンの欠落やローテーション漏れはこのサービスの不備であり、RPC の呼び出し元に、そのトークンが無効だと伝えてはならない。それ以外の `401` は引き続き `UnauthenticatedError` である。

### OPA エンドポイント

`NewOPAEndpoint(baseURL, policyPath)` は `POST {baseURL}/v1/data/{policyPath}` に、入力 `{"resource", "action", "token"}` — トークンは送られたまま — で問い合わせるので、ポリシーがトークンを検証しなければならない。許可するのは、レスポンスの `result` キー（この綴りの大文字小文字どおり）が JSON の `true` を持つときだけである。`result` が無い（OPA の undefined）か `false` なら deny、`result` が真偽値でない、ボディが JSON オブジェクトでない、ボディがサイズ上限を超える、ステータスが `2xx` 以外の場合はエラーである。空の `policyPath` は構築時に拒否される。

| オプション | 効果 |
|---|---|
| `WithOPATimeout(d)` | HTTP クライアントのタイムアウト。デフォルト `10s`。`d` が正でなければ panic する。 |
| `WithOPAMaxResponseBodySize(n)` | レスポンスボディから読むバイト数の上限。デフォルト 1 MiB。`n` が正でなければ panic する。 |
| `WithOPALogLevel(level)` | エンドポイント内部のロガーのレベル。デフォルト `slog.LevelError`。 |
| `WithOPARequestIDHeaderKey(key)` | リクエスト ID を転送するヘッダー。デフォルト `x-request-id`。`""` で転送しない。`key` が `Authorization`、`Content-Type`、`Accept` 以外の RFC 7230 トークンでなければ panic する。 |
| `WithOPAAllowInsecure()` | ループバック以外のホストへの `http://` ベース URL を許可する。 |
| `WithOPATransport(rt)` | リクエストを送るトランスポート。相互 TLS など。デフォルト `http.DefaultTransport`。`rt` が nil なら panic する。 |

### Cedar エンドポイント

`NewCedarEndpoint(baseURL, opts...)` は `POST {baseURL}/v1/is_authorized` に、リゾルバーが返した principal、アクション、リソースを、それぞれ Cedar のエンティティ UID（デフォルトのプレフィックスでは `User::"alice"`、`Action::"read"`、`Resource::"posts/1"`）として、空のコンテキストとともに問い合わせる。許可するのは、レスポンスの `decision` キー（この綴りの大文字小文字どおり）が `"Allow"` のときだけである。それ以外の decision は deny、ボディが JSON オブジェクトでない、ボディがサイズ上限を超える、ステータスが `2xx` 以外の場合はエラーである。`WithCedarPrincipalResolver` が無ければコンストラクターはエラーを返す。

| オプション | 効果 |
|---|---|
| `WithCedarPrincipalResolver(fn)` | **必須。** Bearer トークンを検証し、principal の id を返す。上記を参照。`fn` が nil なら panic する。 |
| `WithCedarPrincipalPrefix(prefix)` | principal のエンティティ型。デフォルト `User`。 |
| `WithCedarActionPrefix(prefix)` | アクションのエンティティ型。デフォルト `Action`。 |
| `WithCedarResourcePrefix(prefix)` | リソースのエンティティ型。デフォルト `Resource`。 |
| `WithCedarTimeout(d)` | HTTP クライアントのタイムアウト。デフォルト `10s`。`d` が正でなければ panic する。 |
| `WithCedarMaxResponseBodySize(n)` | レスポンスボディから読むバイト数の上限。デフォルト 1 MiB。`n` が正でなければ panic する。 |
| `WithCedarLogLevel(level)` | エンドポイント内部のロガーのレベル。デフォルト `slog.LevelError`。 |
| `WithCedarRequestIDHeaderKey(key)` | リクエスト ID を転送するヘッダー。デフォルト `x-request-id`。`""` で転送しない。`key` が `Authorization`、`Content-Type`、`Accept` 以外の RFC 7230 トークンでなければ panic する。 |
| `WithCedarAllowInsecure()` | ループバック以外のホストへの `http://` ベース URL を許可する。 |
| `WithCedarTransport(rt)` | リクエストを送るトランスポート。相互 TLS など。デフォルト `http.DefaultTransport`。`rt` が nil なら panic する。 |

### static エンドポイント

`NewStaticEndpoint(rules)` は、`StaticRule{Resource, Action}` の固定リストに対してローカルで判定する: いずれかのルールが両方に一致すればリクエストを許可する。パターンは完全一致で照合し、`*` は何にでも一致し、`*` で終わるパターンは前方一致で照合する（`posts/*` は `posts/1` に一致する）。コンテキストに Bearer トークンがあることは引き続き要求するが、それ以外にトークンについては何も確認しない。

### エンドポイントのインターフェース

すべてのバックエンドは [`endpoint.VerifierEndpoint`](endpoint/endpoint.go) を実装する: コンテキスト、解決済みのリソース、アクションを受け取る `Verify` で、そのエラーが判定結果になる — `nil` は allow、`*interceptors.DeniedError` は deny、`*interceptors.UnauthenticatedError` はクレデンシャルの拒否、それ以外は判定の失敗である。判定結果の背後にある判定も報告できるエンドポイントは `endpoint.DecisionVerifier` を実装する。

Bearer トークンとリクエスト ID は `context.Context` で渡され、フレームワーク別の `VerificationInterceptor` が設定する（[Bearer トークンとリクエスト ID](#bearer-トークンとリクエスト-id)を参照）。

インターフェースが運ぶのは解決済みのリソースとアクションだけなので、エンドポイントがそれ以外に必要とするものは、自らコンテキストから取り出さなければならない。それをするのは o3co エンドポイントだけである: フレームワークが抽出した `field_mappings` の値をコンテキストに置いていれば、それを `POST /verify` の `context` オブジェクトとして転送する。OPA、Cedar、static エンドポイントはリソースとアクションだけで判定する — [抽出フィールドの転送](#抽出フィールドの転送)を参照。

## 判定の記録

ある操作が*なぜ*許可または拒否されたか — どのルールが決め、どのポリシーリビジョンだったか — を記録しなければならないサービスは、HTTP を解析せずに verifier の判定を受け取れる。判定を報告するのは o3co エンドポイントだけである（`endpoint.DecisionVerifier` を実装している）。OPA、Cedar、static エンドポイント、独自の `VerifierEndpoint` は何も報告せず、それは「不明」と読む。

**ハンドラーで。** RPC が許可されると、判定はハンドラーのコンテキストにある。ストリームでは、ストリームを開いたときの判定である:

```go
if d, ok := interceptors.DecisionFromContext(ctx); ok {
    record(d.RequestID, d.Groups) // alongside the operation it authorized
}
```

`Restricts` が設定されたグループは allow を狭めただけで、何も付与していない: 何がそれを付与したかを記録する場所からは外すこと。v0.16.0 より古い verifier はグループに印を付けないので、そこではすべてのグループで `Restricts` が false になり、そのグループが付与したことを意味しない。

**拒否を含むすべての検査について。** 拒否された RPC のハンドラーは実行されないので、検証インターセプターはオブザーバーも受け取る。オブザーバーは、すべての検査 — ストリームでは、開始時の検査と受信メッセージごとの再検査、両フレームワークで — を、呼び出し元向けに変換する前のエンドポイントのエラーとともに見る:

```go
observe := func(ctx context.Context, ev interceptors.DecisionEvent) {
    // ev.Resource, ev.Action; ev.Decision (nil when nothing was reported);
    // ev.Err (nil when allowed; errors.As finds *interceptors.DeniedError)
}
policygrpc.VerificationInterceptor(verifier, policygrpc.WithDecisionObserver(observe))
policyconnect.VerificationInterceptor(verifier, policyconnect.WithDecisionObserver(observe))
```

拒否のときは、判定は `DeniedError.Decision` にもあり、verifier の deny `code` は `Decision.Code` に入る。

**そのどれも RPC の呼び出し元には届かない。** リビジョンと評価ステータスは、ポリシーセットがいつ変わったか、拒否がエンジンの失敗だったかを語る。呼び出し元が受け取るのは引き続き `PermissionDenied: access denied` であり、このライブラリが返すどのエラーもメッセージに判定を含まない。どのエンドポイントも、デフォルトのレベルではレスポンスボディをログしない — エラー行が示すのはステータス、リクエスト ID、（o3co では）code であり、ボディは `Debug` に出る。

**各ルールが報告したもの。** ポリシーに基づくルールの結果は `Evaluation` を持つが、それは verifier が `verify.evaluationInResponse = "include"` を設定している場合に限られる:

| verifier が送ったもの | `RuleOutcome.Evaluation` | `ConfirmedRevision()` |
|---|---|---|
| `{ "status": "completed", "revision": "sha256:…" }` | `Status: EvaluationCompleted`、`Revision` あり | そのリビジョン、`true` |
| `{ "status": "completed", "revision": null, "loadedRevision": "…" }` | `Status: EvaluationCompleted`、`Revision: ""`、`LoadedRevision` あり | `false` — 何が実行されたかは確定していない |
| `{ "status": "failed", … }` | `Status: EvaluationFailed` | `false` — ルールはフェイルクローズした |
| `{ "status": "not_invoked" }` | `Status: EvaluationNotInvoked` | `false` — 何も評価されていない |
| `evaluation` なし | `nil` | `false` — 不明 |

最後の行は、古い verifier、オプトインしていない verifier、ポリシーソースの無いルールのいずれもが送るものである: 欠落は「不明」を意味し、3 つは見分けがつかない。完了した評価は `DeterminingPolicies` — allow に適用された permit、deny に適用された forbid — を示すこともある。

保存すべきものについての verifier 自身の助言がここにも当てはまる: 各操作について、判定結果、deny code、各評価に伴う理由、送ったリクエスト ID（`Decision.RequestID`）。verifier の `decision` ログイベントは同じリクエスト ID を持つので、2 つの記録はそれで結合できる。verifier は `x-request-id` を、`[A-Za-z0-9-_.:+/=#]` の 128 文字以下である場合にのみ保持し、インターセプターは受信した ID をその形の場合にのみ運び、それ以外では生成するので、送る ID は常に結合できる。

allow にはステータスとボディの両方が必要である: `decision: "allow"` を持つ完全な判定エンベロープをボディとする `200` である。ボディが空、JSON でない、verifier の契約が要求するキーを欠く、値を型付けしている箇所のどこかで null または型違い、deny の `code` や `message` を持つ allow（null であっても）、`WithO3coMaxResponseBodySize` より大きい、読み取り途中で切れている — そうしたものは判定ではなく、何も報告しない。`200` ではそれにより答えは allow ではなくエラーになり、`200` 以外の `2xx`、完全な deny を持つ `200`（これは引き続きオブザーバーに報告される）も同様である。インターセプターはそのエラーを `Internal` に変換する。`403` はボディが何を持っていても deny であり、ボディは理由を報告するだけである。キーは契約の綴りどおりに照合する: 大文字小文字の違うもの（`Passed`、`Decision`）は契約が定義しないキーであり、他の未知のキーと同じく無視されるので、似たキーの代わりにはならない。例外は大文字小文字の違う `restricts` で、無視されずに拒否される: そのときエンベロープは完全ではなく、それを持つ `200` はフェイルクローズする。OPA の `result` と Cedar エージェントの `decision` も、同様に正確なキーでのみ読む。

### 確認済みリビジョンの要求

`WithO3coRequireConfirmedRevision()` は、確認済みのリビジョンに基づくと確定できない allow（`Decision.RevisionConfirmed()`）を拒否する。それはつまり、すべてのグループが通過し、そのうち少なくとも 1 つが付与するグループであり、付与する各グループを満たしたルール — その `satisfiedBy` — が、正しい形のリビジョン付きの完了した評価を報告している、ということである。満たしたルールより前に試された代替は参照しない。制限するグループ（`RuleGroup.Restricts`、verifier の `restricts: true` — たとえば委譲トークンの範囲）は、付与するグループが許すものを狭めるだけで何も付与しないので、それを満たしたものも参照せず、すべてのグループが制限するグループである allow は拒否される。v0.16.0 より古い verifier はグループに印を付けないので、その制限するグループは付与するグループとして検査され、ポリシーソースを持たないため allow を拒否する。拒否された allow は `*interceptors.UnconfirmedRevisionError` を返し、インターセプターはそれを `Internal` に変換する: verifier は許可したが、サービスはその根拠を確定できなかった。拒否には影響しない。

`evaluationInResponse = "include"` を設定していない verifier に対しては、これは**すべての** allow を拒否する。また、付与するグループをポリシーソースの無いルールが満たした allow も拒否するので、付与するルールグループがすべてポリシーに基づくデプロイに向いている。verifier は判定を求められる前にどちらであるかを言えないので、これは構築時には検査しない。代わりに、レスポンスに評価がまったく無かった最初の拒否された allow が、その設定を示すエラーを 1 回ログする。

## ストリーミング

ストリームは、両フレームワークとも**ハンドラーが呼ばれる前に**認可される — 受信より先に送信する双方向・クライアントストリーミングのハンドラーや、一度も受信しないハンドラーも、他と同じく検査される。

その後、ハンドラーが受信する各メッセージについて検査を繰り返す — gRPC では `RecvMsg`、ConnectRPC では `Receive`。リソースとアクションはストリームの間固定なので、この再検査は同じ問いへのセカンドオピニオンではない: ストリームを開いた後に付与が取り消されたり、トークンが期限切れになったりしても受信を続けるストリームを止めるためのものである。再検査はメッセージが届いた後に行うので、取り消し後に届いたメッセージは消去されてハンドラーには渡らず、ハンドラーは代わりに変換されたエラーを受け取る。どのコーデックがデコードしたかは問わない。失敗した受信 — クライアントが自分の側を閉じた、ストリームが壊れた — にはメッセージが無く、再検査しない。受信したメッセージ 1 つにつき verifier の呼び出しが 1 回かかるので、verifier が失敗すればストリームが途中で終わることもある。

送信は再検査しないので、サーバーストリーミングの RPC は、ハンドラーの実行前と、ハンドラーが 1 つのリクエストを読むときに検査され、それ以降は検査されない。

ストリーミング RPC では `field_mappings` に対応していない — ポリシーインターセプターはハンドラーがリクエストメッセージを読む前に動き、クライアントストリームや双方向ストリームには単一のリクエストメッセージが無い — ので、それを宣言したストリーミングメソッドは、両フレームワークとも、解決を試みる前に `Internal` で失敗する。これはプレースホルダーの値の規則とは無関係な恒常的な制限であり、値が受け付けられたかどうかにかかわらず適用される。メッセージごとのアイデンティティが必要なストリーミング RPC は、それをメッセージに載せ、ハンドラーで検査しなければならない。

## proto スキーマ

ポリシーオプションは [`schema/policy.proto`](schema/policy.proto) で定義されている: `google.protobuf.MethodOptions` の拡張 `o3co.authz.v1.policy`（フィールド番号 50000）で、`Policy` — `resource`、`action`、繰り返しの `field_mappings`（それぞれ `placeholder` と、それを埋める `request_field`）— を持つ。生成された Go コードは `schema` パッケージ（Go のパッケージ名は `policy`）である。

サービスの proto で使うには、`policy.proto` を import し、`schema/` ディレクトリを `protoc` のインクルードパスに加える。

## テストヘルパー

`endpointtest` パッケージはテスト用のモックエンドポイントを提供する:

```go
import "github.com/o3co/protobuf.interceptors/endpointtest"

allow := endpointtest.Allow()   // always allows
deny  := endpointtest.Deny()    // always denies
custom := endpointtest.Func(func(ctx context.Context, resource, action string) error {
    // custom logic
    return nil
})

// A DecisionVerifier, for testing what your handler or observer does with a decision.
deciding := endpointtest.Decide(func(ctx context.Context, resource, action string) (*interceptors.Decision, error) {
    return &interceptors.Decision{RequestID: "req-1"}, nil
})
```

## 開発

リポジトリには 3 つのモジュールがあるので、各チェックは `.`、`grpc/`、`connectrpc/` のそれぞれで実行する。フレームワークモジュールはチェックアウト内のコアに対してビルドする（`replace => ../`）ので、コアの変更は両方とあわせてテストされる:

```sh
for dir in . grpc connectrpc; do
  (cd "$dir" && gofmt -l . && go vet ./... && go test ./... -race -count=1)
done
```

CI はさらに staticcheck、`go mod tidy -diff`、govulncheck を、モジュールが対応する Go ツールチェーンで実行する。そのコマンド、protobuf コードの再生成方法、変更が従う規則は [AGENTS.md](AGENTS.md) にある（英語のみ）。

### ワイヤー契約テスト

o3co エンドポイントは、auth.policy-verifier が公開するワイヤー契約 — [`tests/integration/src/conformance/fixtures/wireContract`](https://github.com/o3co/auth.policy-verifier/tree/develop/tests/integration/src/conformance/fixtures/wireContract) — に対して、そのコピーではなく原本でテストされる。CI は `.github/workflows/wire-contract.yml` で pin したリリースの verifier をチェックアウトする。ローカルでテストを実行するには、チェックアウトのそのディレクトリを `O3CO_VERIFIER_WIRE_CONTRACT` に指定する。指定しなければテストはスキップされる:

```sh
O3CO_VERIFIER_WIRE_CONTRACT=../auth.policy-verifier/tests/integration/src/conformance/fixtures/wireContract \
  go test ./... -run WireContract
```

## バージョンとリリース

各モジュールはそれぞれのバージョンとタグを持つ:

| モジュール | タグ | インストール |
|---|---|---|
| コア | `vX.Y.Z` | `go get github.com/o3co/protobuf.interceptors@vX.Y.Z` |
| gRPC | `grpc/vX.Y.Z` | `go get github.com/o3co/protobuf.interceptors/grpc@vX.Y.Z` |
| ConnectRPC | `connectrpc/vX.Y.Z` | `go get github.com/o3co/protobuf.interceptors/connectrpc@vX.Y.Z` |

- **バージョン番号は独立している。** `grpc/v0.4.0` と `v0.4.0` は別のモジュールの別のリリースであり、フレームワークモジュールのバージョンはコアのバージョンについて何も示さない。
- **フレームワークモジュールは、それをリリースしたときのコアのリリース**、つまり当時の最新を require する。フレームワークモジュールを `go get` するとそのコアのバージョンが入る。利用者のモジュールがより新しいものを require していれば、そちらになる。
- **メジャーバージョンが `0` の間は、マイナーリリースで API が壊れることがある。** パッチリリースでは壊れない。マイナーを上げる前にリリースノートを読むこと。
- **リリースノート**は [GitHub Releases](https://github.com/o3co/protobuf.interceptors/releases) で、タグごとに 1 つある。CHANGELOG は無い。
- **撤回（retract）されたバージョン** — `grpc/v0.1.0`、`connectrpc/v0.1.0`、`connectrpc/v0.2.0` は存在しないコアのバージョンを require しており、取得できない。撤回を記したそのモジュールの次のバージョンが公開されると、`go get` は撤回されたバージョンを選ばなくなる。

## ライセンス

Apache License 2.0。[LICENSE](LICENSE) を参照。
