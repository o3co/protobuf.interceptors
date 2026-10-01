module github.com/o3co/protobuf.interceptors/grpc

go 1.25.5

replace github.com/o3co/protobuf.interceptors => ../

require (
	github.com/o3co/protobuf.interceptors v0.4.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260831171406-18b4a7587f8a // indirect
)

// Requires the core module at v0.0.0-00010101000000-000000000000, a version
// that does not exist, so it cannot be fetched.
retract v0.1.0
