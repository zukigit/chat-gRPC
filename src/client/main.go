package main

import (
	"context"
	"fmt"
	"log"
	"syscall"
	"time"

	"github.com/zukigit/chat-gRPC/src/protos/auth"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	address = "localhost:56789"
)

type authClient struct {
	token  string
	client auth.AuthClient
}

func authUnaryInterceptor(token *string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if method != auth.Auth_Login_FullMethodName {
			ctx = metadata.AppendToOutgoingContext(ctx, "auth", "Bearer "+*token)
		}

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func authStreamInterceptor(token *string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if method != auth.Auth_Login_FullMethodName {
			ctx = metadata.AppendToOutgoingContext(ctx, "auth", "Bearer "+*token)
		}

		return streamer(ctx, desc, cc, method, opts...)
	}
}

func newAuthClient() (*authClient, error) {
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc.NewClient failed, err: %s", err.Error())
	}

	return &authClient{
		client: auth.NewAuthClient(conn),
	}, nil
}

func main() {
	fmt.Println("strting client ...")
	var userName, connectUser string

	fmt.Print("userName: ")
	fmt.Scanln(&userName)

	fmt.Print("password: ")
	passwdByte, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}

	authClient, err := newAuthClient()
	if err != nil {
		log.Fatal(err)
	}

	context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Print("connecting ...")
	res, err := authClient.client.Login(context, &auth.LoginRequest{
		UserName: userName,
		Passwd:   string(passwdByte),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("connected, token: %s\n", res.Token)

	fmt.Print("who do you want to connet?(empty for public): ")
	fmt.Scanln(&connectUser)
}
