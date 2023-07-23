package multiserver

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/soheilhy/cmux"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

type ServeHTTP interface {
	ServeHTTP(res http.ResponseWriter, req *http.Request) error
}

type MultiServer struct {
	GrpcWeb    *grpcweb.WrappedGrpcServer
	GrpcServer *grpc.Server
	HttpServer ServeHTTP
}

func (impl *MultiServer) IsGrpcWeb(req *http.Request) bool {
	return impl.GrpcWeb.IsGrpcWebRequest(req) || impl.GrpcWeb.IsGrpcWebSocketRequest(req) || impl.GrpcWeb.IsAcceptableGrpcCorsRequest(req)
}

func (impl *MultiServer) IsPProof(req *http.Request) bool {
	return strings.HasPrefix(req.URL.Path, "/debug/pprof")
}

func (impl *MultiServer) DefereHTTPRecover() {
	if err := recover(); err != nil {
		log.Printf("[server] Recover %v", err)
	}
}

func (impl *MultiServer) DefereHTTPTrace(req *http.Request, start time.Time) {
	log.Printf("%s Duration: %s ", req.URL.Path, time.Since(start))
}

func (impl *MultiServer) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	defer impl.DefereHTTPTrace(req, time.Now())
	defer impl.DefereHTTPRecover()
	if impl.IsGrpcWeb(req) {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/grpc-web")
		impl.GrpcWeb.ServeHTTP(res, req)
		return
	}
	if impl.IsPProof(req) {
		http.DefaultServeMux.ServeHTTP(res, req)
		return
	}
	impl.HttpServer.ServeHTTP(res, req)
}

func (impl *MultiServer) ServeListener(ctx context.Context, l net.Listener) error {
	m := cmux.New(l)
	grpcListener := m.MatchWithWriters(cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"))
	httpListener := m.Match(cmux.Any())
	warperHttp := &http.Server{
		Handler: impl,
	}
	g := errgroup.Group{}
	g.Go(func() error {
		return impl.GrpcServer.Serve(grpcListener)
	})

	g.Go(func() error {
		return warperHttp.Serve(httpListener)
	})

	g.Go(func() error {
		return m.Serve()
	})
	running := true
	g.Go(func() error {
		<-ctx.Done()
		running = false
		m.Close()
		l.Close()
		return nil
	})
	addr := l.Addr().String()
	log.Printf("[Server] running on %s", addr)
	err := g.Wait()
	if err != nil && running {
		return err
	}
	return nil
}

func (impl *MultiServer) ListenAndServe(ctx context.Context, address string) error {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return impl.ServeListener(ctx, l)
}

func warpServer(server *grpc.Server) *grpcweb.WrappedGrpcServer {
	return grpcweb.WrapServer(
		server,
		// Enable CORS
		grpcweb.WithOriginFunc(func(origin string) bool { return true }),
		grpcweb.WithWebsockets(true),
		grpcweb.WithWebsocketOriginFunc(func(req *http.Request) bool {
			return true
		}),
		grpcweb.WithAllowNonRootResource(true),
	)
}

func NewServer(ctx context.Context, grpcServer *grpc.Server, httpServer ServeHTTP) (*MultiServer, error) {
	return &MultiServer{
		GrpcServer: grpcServer,
		GrpcWeb:    warpServer(grpcServer),
		HttpServer: httpServer,
	}, nil
}
