module github.com/o3co/protobuf.interceptors/connectrpc

go 1.25.5

replace github.com/o3co/protobuf.interceptors => ../

require (
	connectrpc.com/connect v1.20.0
	github.com/o3co/protobuf.interceptors v0.2.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260831171406-18b4a7587f8a // indirect
	google.golang.org/grpc v1.83.2 // indirect
)
