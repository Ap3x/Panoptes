// Package pb holds the Go code generated from proto/src/panoptes.proto.
//
// Regenerate with `go generate ./...` from src/detector. It needs protoc (vcpkg ships one in
// build/default/vcpkg_installed/x64-windows/tools/protobuf) and the Go plugins:
//
//	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
//	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
package pb

//go:generate protoc -I ../../../../proto/src --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative panoptes.proto
