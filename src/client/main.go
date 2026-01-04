package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/zukigit/chat-gRPC/src/protos/auth"
	"github.com/zukigit/chat-gRPC/src/protos/chat"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var (
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

		if method != auth.Auth_Login_FullMethodName {
			ctx = metadata.AppendToOutgoingContext(ctx, "auth", *token)
		}

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func authStreamInterceptor(token *string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if token == nil {
			return nil, fmt.Errorf("token is nil")
		}

		if method != auth.Auth_Login_FullMethodName {
			ctx = metadata.AppendToOutgoingContext(ctx, "auth", *token)
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

func (client *client) connect(connectUser string) {
	fmt.Print("connecting ...")
	stream, err := client.chatClient.Connect(context.Background(), &chat.ConnectRequest{
		ConnectUser: connectUser,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("connected")

	for {
		response, err := stream.Recv()
		if err != nil {
			fmt.Println("Stream ended")
			break
		}

		if response.IsPrivate {
			fmt.Printf("%s: %s\n", response.From, response.Message)
		} else {
			fmt.Printf("Public(%s): %s\n", response.From, response.Message)
		}
	}
}

func (client *client) send(connectUser string) {
	var message string = ""
	var err error
	reader := bufio.NewReader(os.Stdin)
	for {
		message = ""

		fmt.Print("message: ")
		message, err = reader.ReadString('\n')
		if err != nil {
			fmt.Println("reading string failed, err:", err.Error())
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = client.chatClient.Send(ctx, &chat.MessageRequest{
			Message: strings.TrimSuffix(message, "\n"),
			To:      connectUser,
		})
		if err != nil {
			fmt.Println("sending message failed, err:", err.Error())
		}
		cancel()
	}
}

func main() {
	var userName, connectUser, mode string

	fmt.Print("server address (default: localhost:56789): ")
	fmt.Scanln(&address)

	fmt.Print("userName: ")
	fmt.Scanln(&userName)

	fmt.Print("password: ")
	passwdByte, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\nmode(send/connect):")
	fmt.Scanln(&mode)

	if mode != "connect" && mode != "send" {
		log.Fatal(fmt.Errorf("unkown mode: %s", mode))
	}

	fmt.Print("who do you want to send or connet?(empty for public): ")
	fmt.Scanln(&connectUser)

	client, err := newClient()
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Print("Logging in ...")
	res, err := client.authClient.Login(ctx, &auth.LoginRequest{
		UserName: userName,
		Passwd:   string(passwdByte),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("done")
	*client.token = res.Token

	if mode == "connect" {
		client.connect(connectUser)
	}

	if mode == "send" {
		client.send(connectUser)
	}
}
