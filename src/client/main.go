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
)

const (
	address = "localhost:56789"
)

type authClient struct {
	client auth.AuthClient
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
