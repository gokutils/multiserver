<!-- Code generated by gomarkdoc. DO NOT EDIT -->

# multiserver

```go
import "github.com/gokutils/multiserver"
```

## Index

- [type MultiServer](<#MultiServer>)
  - [func NewServer\(ctx context.Context, grpcServer \*grpc.Server, httpServer ServeHTTP\) \(\*MultiServer, error\)](<#NewServer>)
  - [func \(impl \*MultiServer\) DefereHTTPRecover\(\)](<#MultiServer.DefereHTTPRecover>)
  - [func \(impl \*MultiServer\) DefereHTTPTrace\(req \*http.Request, start time.Time\)](<#MultiServer.DefereHTTPTrace>)
  - [func \(impl \*MultiServer\) IsGrpcWeb\(req \*http.Request\) bool](<#MultiServer.IsGrpcWeb>)
  - [func \(impl \*MultiServer\) IsPProof\(req \*http.Request\) bool](<#MultiServer.IsPProof>)
  - [func \(impl \*MultiServer\) ListenAndServe\(ctx context.Context, address string\) error](<#MultiServer.ListenAndServe>)
  - [func \(impl \*MultiServer\) ServeHTTP\(res http.ResponseWriter, req \*http.Request\)](<#MultiServer.ServeHTTP>)
  - [func \(impl \*MultiServer\) ServeListener\(ctx context.Context, l net.Listener\) error](<#MultiServer.ServeListener>)
- [type ServeHTTP](<#ServeHTTP>)


<a name="MultiServer"></a>
## type MultiServer



```go
type MultiServer struct {
    GrpcWeb    *grpcweb.WrappedGrpcServer
    GrpcServer *grpc.Server
    HttpServer ServeHTTP
}
```

<a name="NewServer"></a>
### func NewServer

```go
func NewServer(ctx context.Context, grpcServer *grpc.Server, httpServer ServeHTTP) (*MultiServer, error)
```



<a name="MultiServer.DefereHTTPRecover"></a>
### func \(\*MultiServer\) DefereHTTPRecover

```go
func (impl *MultiServer) DefereHTTPRecover()
```



<a name="MultiServer.DefereHTTPTrace"></a>
### func \(\*MultiServer\) DefereHTTPTrace

```go
func (impl *MultiServer) DefereHTTPTrace(req *http.Request, start time.Time)
```



<a name="MultiServer.IsGrpcWeb"></a>
### func \(\*MultiServer\) IsGrpcWeb

```go
func (impl *MultiServer) IsGrpcWeb(req *http.Request) bool
```



<a name="MultiServer.IsPProof"></a>
### func \(\*MultiServer\) IsPProof

```go
func (impl *MultiServer) IsPProof(req *http.Request) bool
```



<a name="MultiServer.ListenAndServe"></a>
### func \(\*MultiServer\) ListenAndServe

```go
func (impl *MultiServer) ListenAndServe(ctx context.Context, address string) error
```



<a name="MultiServer.ServeHTTP"></a>
### func \(\*MultiServer\) ServeHTTP

```go
func (impl *MultiServer) ServeHTTP(res http.ResponseWriter, req *http.Request)
```



<a name="MultiServer.ServeListener"></a>
### func \(\*MultiServer\) ServeListener

```go
func (impl *MultiServer) ServeListener(ctx context.Context, l net.Listener) error
```



<a name="ServeHTTP"></a>
## type ServeHTTP



```go
type ServeHTTP interface {
    ServeHTTP(res http.ResponseWriter, req *http.Request) error
}
```

Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)