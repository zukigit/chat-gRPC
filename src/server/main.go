package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zukigit/chat-gRPC/src/protos/auth"
	"github.com/zukigit/chat-gRPC/src/protos/chat"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	address = ":56789"
)

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (ss *serverStream) Context() context.Context {
	return ss.ctx
}

type server struct {
	secretKey []byte
	mu        sync.RWMutex
	users     map[string]*auth.User
	auth.UnimplementedAuthServer
	chat.UnimplementedChatServer
}

func (s *server) register(user *auth.User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user != nil {
		s.users[user.GetUserName()] = user
	}
}

func (s *server) validateToken(requestToken string) (jwt.Claims, error) {
	token, err := jwt.ParseWithClaims(requestToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return s.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("could not get claims, Unknown type: %T", token.Claims)
	}

	if token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *server) generateToken(userName string) (string, error) {
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "auth",
		Subject:   userName,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func AuthUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	if info.FullMethod == auth.Auth_Login_FullMethodName {
		return handler(ctx, req)
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing meta data")
	}

	values := md.Get("auth")

	if len(values) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing auth token")
	}

	// Extract token from "Bearer <token>" format
	requestToken := values[0]
	if len(requestToken) > 7 && requestToken[:7] == "Bearer" {
		requestToken = requestToken[7:]
	}

	srv, ok := info.Server.(*server)
	if !ok {
		return nil, status.Errorf(codes.Internal, "could not get server from UnaryServerInfo")
	}

	claims, err := srv.validateToken(requestToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Token Validation failed, err: %s", err.Error())
	}

	// Add claims to context for use in handlers
	ctx = context.WithValue(ctx, "claims", claims)

	return handler(ctx, req)
}

func AuthStreamServerInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if info.FullMethod == auth.Auth_Login_FullMethodName {
		return handler(srv, ss)
	}

	md, ok := metadata.FromIncomingContext(ss.Context())
	if !ok {
		return status.Errorf(codes.Unauthenticated, "missing meta data")
	}

	values := md.Get("auth")

	if len(values) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing auth token")
	}

	// Extract token from "Bearer <token>" format
	requestToken := values[0]
	if len(requestToken) > 7 && requestToken[:7] == "Bearer" {
		requestToken = requestToken[7:]
	}

	server, ok := srv.(*server)
	if !ok {
		return status.Errorf(codes.Internal, "could not get server from UnaryServerInfo")
	}

	claims, err := server.validateToken(requestToken)
	if err != nil {
		return status.Errorf(codes.Internal, "token Validation failed, err: %s", err.Error())
	}

	ctx := context.WithValue(ss.Context(), "claims", claims)

	wrappedSs := &serverStream{
		ServerStream: ss,
		ctx:          ctx,
	}

	return handler(srv, wrappedSs)
}

func (s *server) Login(ctx context.Context, requestUser *auth.User) (*auth.LoginResponse, error) {
	user, exists := s.users[requestUser.GetUserName()]
	if !exists {
		user = &auth.User{
			UserName: requestUser.UserName,
			Passwd:   requestUser.Passwd,
			IsActive: false,
		}
		s.register(user)
	}

	if user.GetPasswd() != requestUser.GetPasswd() {
		return nil, status.Errorf(codes.Unauthenticated, "invalid username or password")
	}

	token, err := s.generateToken(user.GetUserName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not generate token")
	}

	return &auth.LoginResponse{
		Token: token,
	}, nil
}

func (s *server) Send(ctx context.Context, req *chat.MessageRequest) (*chat.MessageRespone, error) {
	return &chat.MessageRespone{
		Success: true,
	}, nil
}

func (s *server) Connect(req *chat.Empty, stream grpc.ServerStreamingServer[chat.MessageRequest]) error {
	claims, ok := stream.Context().Value("claims").(*jwt.RegisteredClaims)
	if !ok {
		return status.Errorf(codes.Internal, "could not get RegisteredClaims, Unknown type: %T", claims)
	}

	userName := claims.Subject

	log.Printf("Streaming response for user: %s", userName)

	for i := 0; i < 5; i++ {
		message := &chat.MessageRequest{
			Message: fmt.Sprintf("testing %d", i),
		}
		err := stream.Send(message)
		if err != nil {
			return err
		}

		time.Sleep(2 * time.Second)
	}

	return nil
}

func main() {
	fmt.Println("starting server")

	srv := &server{
		users:     make(map[string]*auth.User),
		secretKey: []byte("no_secret"),
	}

	s := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
			return AuthUnaryInterceptor(ctx, req, info, handler)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			return AuthStreamServerInterceptor(srv, ss, info, handler)
		}),
	)
	auth.RegisterAuthServer(s, srv)
	chat.RegisterChatServer(s, srv)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("Server listening at %v", listener.Addr())

	s.Serve(listener)
}
