module github.com/o3co/protobuf.interceptors/grpc

go 1.26.0

replace github.com/o3co/protobuf.interceptors => ../

require (
	github.com/o3co/protobuf.interceptors v0.7.0
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260831171406-18b4a7587f8a // indirect
)

// Requires the core module at v0.0.0-00010101000000-000000000000, a version
// that does not exist, so it cannot be built or required.
retract v0.1.0
