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

type user struct {
	userName    string
	passwd      string
	isActive    bool
	messageChan chan *chat.MessageRequest
}

type server struct {
	secretKey      []byte
	mu             sync.RWMutex
	users          map[string]*user
	activeChannels map[string]chan chat.MessageRequest
	auth.UnimplementedAuthServer
	chat.UnimplementedChatServer
}

func (s *server) setActiveUser(userId string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exist := s.users[userId]
	if exist {
		user.isActive = true
	}
}

func (s *server) setNonActiveUser(userId string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exist := s.users[userId]
	if exist {
		user.isActive = false
	}
}

func (s *server) register(user *user) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user != nil {
		s.users[user.userName] = user
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

	_, exist := s.users[claims.Subject]
	if !exist {
		return nil, fmt.Errorf("user %s does not exist, call Login again", claims.Subject)
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

func (s *server) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	regUser, exists := s.users[req.GetUserName()]
	if !exists {
		regUser = &user{
			userName:    req.UserName,
			passwd:      req.Passwd,
			isActive:    false,
			messageChan: make(chan *chat.MessageRequest, 100),
		}
		s.register(regUser)
	}

	if regUser.passwd != req.GetPasswd() {
		return nil, status.Errorf(codes.Unauthenticated, "invalid username or password")
	}

	token, err := s.generateToken(regUser.userName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not generate token")
	}

	return &auth.LoginResponse{
		Token: token,
	}, nil
}

func (s *server) Send(ctx context.Context, req *chat.MessageRequest) (*chat.MessageRespone, error) {
	claims, ok := ctx.Value("claims").(*jwt.RegisteredClaims)
	if !ok {
		return nil, status.Errorf(codes.Internal, "could not get RegisteredClaims, Unknown type: %T", claims)
	}

	if req == nil {
		return nil, status.Errorf(codes.Internal, "MessageRequest is nil")
	}

	req.From = claims.Subject

	if req.To != "" && req.To != claims.Subject {
		user, exist := s.users[req.To]
		if !exist {
			return nil, status.Errorf(codes.Internal, "request user %s does not exist", req.To)
		}

		user.messageChan <- req
	} else {
		// send message to public channel
		for _, user := range s.users {
			if user.userName != claims.Subject {
				user.messageChan <- req
			}
		}
	}

	// send message to self
	user, exist := s.users[claims.Subject]
	if exist {
		user.messageChan <- req
	}

	return &chat.MessageRespone{
		Success: true,
	}, nil
}

func (s *server) Connect(req *chat.ConnectRequest, stream grpc.ServerStreamingServer[chat.MessageRequest]) error {
	claims, ok := stream.Context().Value("claims").(*jwt.RegisteredClaims)
	if !ok {
		return status.Errorf(codes.Internal, "could not get RegisteredClaims, Unknown type: %T", claims)
	}

	for {
		select {
		case <-stream.Context().Done():
			// Client disconnected, exit cleanly
			return stream.Context().Err()
		case message, ok := <-s.users[claims.Subject].messageChan:
			if !ok {
				return nil
			}

			// check who sent the message
			if req.ConnectUser != "" && req.ConnectUser != message.From && claims.Subject != message.From {
				continue
			}

			err := stream.Send(message)
			if err != nil {
				return err
			}
		}
	}
}

func main() {
	fmt.Println("starting server")

	srv := &server{
		users:     make(map[string]*user),
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
