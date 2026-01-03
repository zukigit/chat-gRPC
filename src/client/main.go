package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zukigit/chat-gRPC/src/protos/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	address = "localhost:56789"
)

type authClient struct {
	client auth.AuthClient
}

func main() {
	fmt.Println("strting client ...")

	context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &auth.LoginRequest{
		UserName: "zuki",
		Passwd:   "123123",
	}

	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatal(err)
	}

	authClient := &authClient{
		client: auth.NewAuthClient(conn),
	}

	res, err := authClient.client.Login(context, req)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(res.Token)
}
