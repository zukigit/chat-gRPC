package main

import (
	"context"
	"fmt"
	"log"
	"syscall"
	"time"

	"github.com/zukigit/chat-gRPC/src/protos/auth"
	"github.com/zukigit/chat-gRPC/src/protos/chat"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	address = "localhost:56789"
)

type client struct {
	token      *string
	authClient auth.AuthClient
	chatClient chat.ChatClient
}

func authUnaryInterceptor(token *string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if token == nil {
			return fmt.Errorf("token is nil")
		}

		fmt.Println("token", *token)

		if method != auth.Auth_Login_FullMethodName {
			ctx = metadata.AppendToOutgoingContext(ctx, "auth", *token)
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

func newClient() (*client, error) {
	token := ""
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(authUnaryInterceptor(&token)),
		grpc.WithStreamInterceptor(authStreamInterceptor(&token)),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc.NewClient failed, err: %s", err.Error())
	}

	return &client{
		authClient: auth.NewAuthClient(conn),
		chatClient: chat.NewChatClient(conn),
		token:      &token,
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

	client, err := newClient()
	if err != nil {
		log.Fatal(err)
	}

	context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Print("connecting ...")
	res, err := client.authClient.Login(context, &auth.LoginRequest{
		UserName: userName,
		Passwd:   string(passwdByte),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("connected, token: %s\n", res.Token)
	*client.token = res.Token

	fmt.Print("who do you want to connet?(empty for public): ")
	fmt.Scanln(&connectUser)

	msgRes, err := client.chatClient.Send(context, &chat.MessageRequest{
		Message: "hello",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("msgRes.Success", msgRes.Success)
}
