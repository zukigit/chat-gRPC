# gRPC practice repo

## init project
- install
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```
- update PATH
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```