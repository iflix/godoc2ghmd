use 'godoc cmd/net/http' for documentation on the net/http command 

# http
`import "net/http"`

* [Overview](#pkg-overview)
* [Imported Packages](#pkg-imports)
* [Index](#pkg-index)
* [Examples](#pkg-examples)

## <a name="pkg-overview">Overview</a>
Package http provides HTTP client and server implementations.

Get, Head, Post, and PostForm make HTTP (or HTTPS) requests:

	resp, err := http.Get("<a href="http://example.com/">http://example.com/</a>")
	...
	resp, err := http.Post("<a href="http://example.com/upload">http://example.com/upload</a>", "image/jpeg", &buf)
	...
	resp, err := http.PostForm("<a href="http://example.com/form">http://example.com/form</a>",
		url.Values{"key": {"Value"}, "id": {"123"}})

The client must close the response body when finished with it:

	resp, err := http.Get("<a href="http://example.com/">http://example.com/</a>")
	if err != nil {
		// handle error
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	// ...

For control over HTTP client headers, redirect policy, and other
settings, create a Client:

	client := &http.Client{
		CheckRedirect: redirectPolicyFunc,
	}
	
	resp, err := client.Get("<a href="http://example.com">http://example.com</a>")
	// ...
	
	req, err := http.NewRequest("GET", "<a href="http://example.com">http://example.com</a>", nil)
	// ...
	req.Header.Add("If-None-Match", `W/"wyzzy"`)
	resp, err := client.Do(req)
	// ...

For control over proxies, TLS configuration, keep-alives,
compression, and other settings, create a Transport:

	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{RootCAs: pool},
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("<a href="https://example.com">https://example.com</a>")

Clients and Transports are safe for concurrent use by multiple
goroutines and for efficiency should only be created once and re-used.

ListenAndServe starts an HTTP server with a given address and handler.
The handler is usually nil, which means to use DefaultServeMux.
Handle and HandleFunc add handlers to DefaultServeMux:

	http.Handle("/foo", fooHandler)
	
	http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})
	
	log.Fatal(http.ListenAndServe(":8080", nil))

More control over the server's behavior is available by creating a
custom Server:

	s := &http.Server{
		Addr:           ":8080",
		Handler:        myHandler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())

The http package has transparent support for the HTTP/2 protocol when
using HTTPS. Programs that must disable HTTP/2 can do so by setting
Transport.TLSNextProto (for clients) or Server.TLSNextProto (for
servers) to a non-nil, empty map. Alternatively, the following GODEBUG
environment variables are currently supported:

	GODEBUG=http2client=0  # disable HTTP/2 client support
	GODEBUG=http2server=0  # disable HTTP/2 server support
	GODEBUG=http2debug=1   # enable verbose HTTP/2 debug logs
	GODEBUG=http2debug=2   # ... even more verbose, with frame dumps

The GODEBUG variables are not covered by Go's API compatibility promise.
HTTP/2 support was added in Go 1.6. Please report any issues instead of
disabling HTTP/2 support: <a href="https://golang.org/s/http2bug">https://golang.org/s/http2bug</a>

## <a name="pkg-imports">Imported Packages</a>

- golang_org/x/net/http2/hpack
- golang_org/x/net/lex/httplex

## <a name="pkg-index">Index</a>
* [Constants](#pkg-constants)
* [Variables](#pkg-variables)
* [func CanonicalHeaderKey(s string) string](#CanonicalHeaderKey)
* [func DetectContentType(data []byte) string](#DetectContentType)
* [func Error(w ResponseWriter, error string, code int)](#Error)
* [func Handle(pattern string, handler Handler)](#Handle)
* [func HandleFunc(pattern string, handler func(ResponseWriter, \*Request))](#HandleFunc)
* [func ListenAndServe(addr string, handler Handler) error](#ListenAndServe)
* [func ListenAndServeTLS(addr, certFile, keyFile string, handler Handler) error](#ListenAndServeTLS)
* [func MaxBytesReader(w ResponseWriter, r io.ReadCloser, n int64) io.ReadCloser](#MaxBytesReader)
* [func NotFound(w ResponseWriter, r \*Request)](#NotFound)
* [func ParseHTTPVersion(vers string) (major, minor int, ok bool)](#ParseHTTPVersion)
* [func ParseTime(text string) (t time.Time, err error)](#ParseTime)
* [func ProxyFromEnvironment(req \*Request) (\*url.URL, error)](#ProxyFromEnvironment)
* [func ProxyURL(fixedURL \*url.URL) func(\*Request) (\*url.URL, error)](#ProxyURL)
* [func Redirect(w ResponseWriter, r \*Request, urlStr string, code int)](#Redirect)
* [func Serve(l net.Listener, handler Handler) error](#Serve)
* [func ServeContent(w ResponseWriter, req \*Request, name string, modtime time.Time, content io.ReadSeeker)](#ServeContent)
* [func ServeFile(w ResponseWriter, r \*Request, name string)](#ServeFile)
* [func SetCookie(w ResponseWriter, cookie \*Cookie)](#SetCookie)
* [func StatusText(code int) string](#StatusText)
* [type Client](#Client)
  * [func (c \*Client) Do(req \*Request) (\*Response, error)](#Client.Do)
  * [func (c \*Client) Get(url string) (resp \*Response, err error)](#Client.Get)
  * [func (c \*Client) Head(url string) (resp \*Response, err error)](#Client.Head)
  * [func (c \*Client) Post(url string, bodyType string, body io.Reader) (resp \*Response, err error)](#Client.Post)
  * [func (c \*Client) PostForm(url string, data url.Values) (resp \*Response, err error)](#Client.PostForm)
* [type CloseNotifier](#CloseNotifier)
* [type ConnState](#ConnState)
  * [func (c ConnState) String() string](#ConnState.String)
* [type Cookie](#Cookie)
  * [func (c \*Cookie) String() string](#Cookie.String)
* [type CookieJar](#CookieJar)
* [type Dir](#Dir)
  * [func (d Dir) Open(name string) (File, error)](#Dir.Open)
* [type File](#File)
* [type FileSystem](#FileSystem)
* [type Flusher](#Flusher)
* [type Handler](#Handler)
  * [func FileServer(root FileSystem) Handler](#FileServer)
  * [func NotFoundHandler() Handler](#NotFoundHandler)
  * [func RedirectHandler(url string, code int) Handler](#RedirectHandler)
  * [func StripPrefix(prefix string, h Handler) Handler](#StripPrefix)
  * [func TimeoutHandler(h Handler, dt time.Duration, msg string) Handler](#TimeoutHandler)
* [type HandlerFunc](#HandlerFunc)
  * [func (f HandlerFunc) ServeHTTP(w ResponseWriter, r \*Request)](#HandlerFunc.ServeHTTP)
* [type Header](#Header)
  * [func (h Header) Add(key, value string)](#Header.Add)
  * [func (h Header) Del(key string)](#Header.Del)
  * [func (h Header) Get(key string) string](#Header.Get)
  * [func (h Header) Set(key, value string)](#Header.Set)
  * [func (h Header) Write(w io.Writer) error](#Header.Write)
  * [func (h Header) WriteSubset(w io.Writer, exclude map[string]bool) error](#Header.WriteSubset)
* [type Hijacker](#Hijacker)
* [type ProtocolError](#ProtocolError)
  * [func (err \*ProtocolError) Error() string](#ProtocolError.Error)
* [type Request](#Request)
  * [func NewRequest(method, urlStr string, body io.Reader) (\*Request, error)](#NewRequest)
  * [func ReadRequest(b \*bufio.Reader) (\*Request, error)](#ReadRequest)
  * [func (r \*Request) AddCookie(c \*Cookie)](#Request.AddCookie)
  * [func (r \*Request) BasicAuth() (username, password string, ok bool)](#Request.BasicAuth)
  * [func (r \*Request) Context() context.Context](#Request.Context)
  * [func (r \*Request) Cookie(name string) (\*Cookie, error)](#Request.Cookie)
  * [func (r \*Request) Cookies() []\*Cookie](#Request.Cookies)
  * [func (r \*Request) FormFile(key string) (multipart.File, \*multipart.FileHeader, error)](#Request.FormFile)
  * [func (r \*Request) FormValue(key string) string](#Request.FormValue)
  * [func (r \*Request) MultipartReader() (\*multipart.Reader, error)](#Request.MultipartReader)
  * [func (r \*Request) ParseForm() error](#Request.ParseForm)
  * [func (r \*Request) ParseMultipartForm(maxMemory int64) error](#Request.ParseMultipartForm)
  * [func (r \*Request) PostFormValue(key string) string](#Request.PostFormValue)
  * [func (r \*Request) ProtoAtLeast(major, minor int) bool](#Request.ProtoAtLeast)
  * [func (r \*Request) Referer() string](#Request.Referer)
  * [func (r \*Request) SetBasicAuth(username, password string)](#Request.SetBasicAuth)
  * [func (r \*Request) UserAgent() string](#Request.UserAgent)
  * [func (r \*Request) WithContext(ctx context.Context) \*Request](#Request.WithContext)
  * [func (r \*Request) Write(w io.Writer) error](#Request.Write)
  * [func (r \*Request) WriteProxy(w io.Writer) error](#Request.WriteProxy)
* [type Response](#Response)
  * [func Get(url string) (resp \*Response, err error)](#Get)
  * [func Head(url string) (resp \*Response, err error)](#Head)
  * [func Post(url string, bodyType string, body io.Reader) (resp \*Response, err error)](#Post)
  * [func PostForm(url string, data url.Values) (resp \*Response, err error)](#PostForm)
  * [func ReadResponse(r \*bufio.Reader, req \*Request) (\*Response, error)](#ReadResponse)
  * [func (r \*Response) Cookies() []\*Cookie](#Response.Cookies)
  * [func (r \*Response) Location() (\*url.URL, error)](#Response.Location)
  * [func (r \*Response) ProtoAtLeast(major, minor int) bool](#Response.ProtoAtLeast)
  * [func (r \*Response) Write(w io.Writer) error](#Response.Write)
* [type ResponseWriter](#ResponseWriter)
* [type RoundTripper](#RoundTripper)
  * [func NewFileTransport(fs FileSystem) RoundTripper](#NewFileTransport)
* [type ServeMux](#ServeMux)
  * [func NewServeMux() \*ServeMux](#NewServeMux)
  * [func (mux \*ServeMux) Handle(pattern string, handler Handler)](#ServeMux.Handle)
  * [func (mux \*ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, \*Request))](#ServeMux.HandleFunc)
  * [func (mux \*ServeMux) Handler(r \*Request) (h Handler, pattern string)](#ServeMux.Handler)
  * [func (mux \*ServeMux) ServeHTTP(w ResponseWriter, r \*Request)](#ServeMux.ServeHTTP)
* [type Server](#Server)
  * [func (srv \*Server) ListenAndServe() error](#Server.ListenAndServe)
  * [func (srv \*Server) ListenAndServeTLS(certFile, keyFile string) error](#Server.ListenAndServeTLS)
  * [func (srv \*Server) Serve(l net.Listener) error](#Server.Serve)
  * [func (srv \*Server) SetKeepAlivesEnabled(v bool)](#Server.SetKeepAlivesEnabled)
* [type Transport](#Transport)
  * [func (t \*Transport) CancelRequest(req \*Request)](#Transport.CancelRequest)
  * [func (t \*Transport) CloseIdleConnections()](#Transport.CloseIdleConnections)
  * [func (t \*Transport) RegisterProtocol(scheme string, rt RoundTripper)](#Transport.RegisterProtocol)
  * [func (t \*Transport) RoundTrip(req \*Request) (\*Response, error)](#Transport.RoundTrip)

#### <a name="pkg-examples">Examples</a>
* [FileServer](#example_FileServer)
* [FileServer (StripPrefix)](#example_FileServer_stripPrefix)
* [Get](#example_Get)
* [Hijacker](#example_Hijacker)
* [ResponseWriter (Trailers)](#example_ResponseWriter_trailers)
* [ServeMux.Handle](#example_ServeMux_Handle)
* [StripPrefix](#example_StripPrefix)

#### <a name="pkg-files">Package files</a>
[client.go](./client.go) [cookie.go](./cookie.go) [doc.go](./doc.go) [filetransport.go](./filetransport.go) [fs.go](./fs.go) [h2_bundle.go](./h2_bundle.go) [header.go](./header.go) [http.go](./http.go) [jar.go](./jar.go) [method.go](./method.go) [request.go](./request.go) [response.go](./response.go) [server.go](./server.go) [sniff.go](./sniff.go) [status.go](./status.go) [transfer.go](./transfer.go) [transport.go](./transport.go) 

## <a name="pkg-constants">Constants</a>
``` go
const (
    MethodGet     = "GET"
    MethodHead    = "HEAD"
    MethodPost    = "POST"
    MethodPut     = "PUT"
    MethodPatch   = "PATCH" // RFC 5789
    MethodDelete  = "DELETE"
    MethodConnect = "CONNECT"
    MethodOptions = "OPTIONS"
    MethodTrace   = "TRACE"
)
```
Common HTTP methods.

Unless otherwise noted, these are defined in RFC 7231 section 4.3.

``` go
const (
    StatusContinue           = 100 // RFC 7231, 6.2.1
    StatusSwitchingProtocols = 101 // RFC 7231, 6.2.2
    StatusProcessing         = 102 // RFC 2518, 10.1

    StatusOK                   = 200 // RFC 7231, 6.3.1
    StatusCreated              = 201 // RFC 7231, 6.3.2
    StatusAccepted             = 202 // RFC 7231, 6.3.3
    StatusNonAuthoritativeInfo = 203 // RFC 7231, 6.3.4
    StatusNoContent            = 204 // RFC 7231, 6.3.5
    StatusResetContent         = 205 // RFC 7231, 6.3.6
    StatusPartialContent       = 206 // RFC 7233, 4.1
    StatusMultiStatus          = 207 // RFC 4918, 11.1
    StatusAlreadyReported      = 208 // RFC 5842, 7.1
    StatusIMUsed               = 226 // RFC 3229, 10.4.1

    StatusMultipleChoices  = 300 // RFC 7231, 6.4.1
    StatusMovedPermanently = 301 // RFC 7231, 6.4.2
    StatusFound            = 302 // RFC 7231, 6.4.3
    StatusSeeOther         = 303 // RFC 7231, 6.4.4
    StatusNotModified      = 304 // RFC 7232, 4.1
    StatusUseProxy         = 305 // RFC 7231, 6.4.5

    StatusTemporaryRedirect = 307 // RFC 7231, 6.4.7
    StatusPermanentRedirect = 308 // RFC 7538, 3

    StatusBadRequest                   = 400 // RFC 7231, 6.5.1
    StatusUnauthorized                 = 401 // RFC 7235, 3.1
    StatusPaymentRequired              = 402 // RFC 7231, 6.5.2
    StatusForbidden                    = 403 // RFC 7231, 6.5.3
    StatusNotFound                     = 404 // RFC 7231, 6.5.4
    StatusMethodNotAllowed             = 405 // RFC 7231, 6.5.5
    StatusNotAcceptable                = 406 // RFC 7231, 6.5.6
    StatusProxyAuthRequired            = 407 // RFC 7235, 3.2
    StatusRequestTimeout               = 408 // RFC 7231, 6.5.7
    StatusConflict                     = 409 // RFC 7231, 6.5.8
    StatusGone                         = 410 // RFC 7231, 6.5.9
    StatusLengthRequired               = 411 // RFC 7231, 6.5.10
    StatusPreconditionFailed           = 412 // RFC 7232, 4.2
    StatusRequestEntityTooLarge        = 413 // RFC 7231, 6.5.11
    StatusRequestURITooLong            = 414 // RFC 7231, 6.5.12
    StatusUnsupportedMediaType         = 415 // RFC 7231, 6.5.13
    StatusRequestedRangeNotSatisfiable = 416 // RFC 7233, 4.4
    StatusExpectationFailed            = 417 // RFC 7231, 6.5.14
    StatusTeapot                       = 418 // RFC 7168, 2.3.3
    StatusUnprocessableEntity          = 422 // RFC 4918, 11.2
    StatusLocked                       = 423 // RFC 4918, 11.3
    StatusFailedDependency             = 424 // RFC 4918, 11.4
    StatusUpgradeRequired              = 426 // RFC 7231, 6.5.15
    StatusPreconditionRequired         = 428 // RFC 6585, 3
    StatusTooManyRequests              = 429 // RFC 6585, 4
    StatusRequestHeaderFieldsTooLarge  = 431 // RFC 6585, 5
    StatusUnavailableForLegalReasons   = 451 // RFC 7725, 3

    StatusInternalServerError           = 500 // RFC 7231, 6.6.1
    StatusNotImplemented                = 501 // RFC 7231, 6.6.2
    StatusBadGateway                    = 502 // RFC 7231, 6.6.3
    StatusServiceUnavailable            = 503 // RFC 7231, 6.6.4
    StatusGatewayTimeout                = 504 // RFC 7231, 6.6.5
    StatusHTTPVersionNotSupported       = 505 // RFC 7231, 6.6.6
    StatusVariantAlsoNegotiates         = 506 // RFC 2295, 8.1
    StatusInsufficientStorage           = 507 // RFC 4918, 11.5
    StatusLoopDetected                  = 508 // RFC 5842, 7.2
    StatusNotExtended                   = 510 // RFC 2774, 7
    StatusNetworkAuthenticationRequired = 511 // RFC 6585, 6
)
```
HTTP status codes as registered with IANA.
See: <a href="http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml">http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml</a>

``` go
const DefaultMaxHeaderBytes = 1 << 20 // 1 MB

```
DefaultMaxHeaderBytes is the maximum permitted size of the headers
in an HTTP request.
This can be overridden by setting Server.MaxHeaderBytes.

``` go
const DefaultMaxIdleConnsPerHost = 2
```
DefaultMaxIdleConnsPerHost is the default value of Transport's
MaxIdleConnsPerHost.

``` go
const TimeFormat = "Mon, 02 Jan 2006 15:04:05 GMT"
```
TimeFormat is the time format to use when generating times in HTTP
headers. It is like time.RFC1123 but hard-codes GMT as the time
zone. The time being formatted must be in UTC for Format to
generate the correct format.

For parsing this time format, see ParseTime.

## <a name="pkg-variables">Variables</a>
``` go
var (
    ErrHeaderTooLong        = &ProtocolError{"header too long"}
    ErrShortBody            = &ProtocolError{"entity body too short"}
    ErrNotSupported         = &ProtocolError{"feature not supported"}
    ErrUnexpectedTrailer    = &ProtocolError{"trailer header without chunked transfer encoding"}
    ErrMissingContentLength = &ProtocolError{"missing ContentLength in HEAD response"}
    ErrNotMultipart         = &ProtocolError{"request Content-Type isn't multipart/form-data"}
    ErrMissingBoundary      = &ProtocolError{"no multipart boundary param in Content-Type"}
)
```
``` go
var (
    // ErrBodyNotAllowed is returned by ResponseWriter.Write calls
    // when the HTTP method or response code does not permit a
    // body.
    ErrBodyNotAllowed = errors.New("http: request method or response status code does not allow body")

    // ErrHijacked is returned by ResponseWriter.Write calls when
    // the underlying connection has been hijacked using the
    // Hijacker interfaced.
    ErrHijacked = errors.New("http: connection has been hijacked")

    // ErrContentLength is returned by ResponseWriter.Write calls
    // when a Handler set a Content-Length response header with a
    // declared size and then attempted to write more bytes than
    // declared.
    ErrContentLength = errors.New("http: wrote more than the declared Content-Length")

    // Deprecated: ErrWriteAfterFlush is no longer used.
    ErrWriteAfterFlush = errors.New("unused")
)
```
Errors used by the HTTP server.

``` go
var (
    // ServerContextKey is a context key. It can be used in HTTP
    // handlers with context.WithValue to access the server that
    // started the handler. The associated value will be of
    // type *Server.
    ServerContextKey = &contextKey{"http-server"}

    // LocalAddrContextKey is a context key. It can be used in
    // HTTP handlers with context.WithValue to access the address
    // the local address the connection arrived on.
    // The associated value will be of type net.Addr.
    LocalAddrContextKey = &contextKey{"local-addr"}
)
```
``` go
var DefaultClient = &Client{}
```
DefaultClient is the default Client and is used by Get, Head, and Post.

``` go
var DefaultServeMux = &defaultServeMux
```
DefaultServeMux is the default ServeMux used by Serve.

``` go
var ErrBodyReadAfterClose = errors.New("http: invalid Read on closed Body")
```
ErrBodyReadAfterClose is returned when reading a Request or Response
Body after the body has been closed. This typically happens when the body is
read after an HTTP Handler calls WriteHeader or Write on its
ResponseWriter.

``` go
var ErrHandlerTimeout = errors.New("http: Handler timeout")
```
ErrHandlerTimeout is returned on ResponseWriter Write calls
in handlers which have timed out.

``` go
var ErrLineTooLong = internal.ErrLineTooLong
```
ErrLineTooLong is returned when reading request or response bodies
with malformed chunked encoding.

``` go
var ErrMissingFile = errors.New("http: no such file")
```
ErrMissingFile is returned by FormFile when the provided file field name
is either not present in the request or not a file field.

``` go
var ErrNoCookie = errors.New("http: named cookie not present")
```
ErrNoCookie is returned by Request's Cookie method when a cookie is not found.

``` go
var ErrNoLocation = errors.New("http: no Location header in response")
```
ErrNoLocation is returned by Response's Location method
when no Location header is present.

``` go
var ErrSkipAltProtocol = errors.New("net/http: skip alternate protocol")
```
ErrSkipAltProtocol is a sentinel error value defined by Transport.RegisterProtocol.

``` go
var ErrUseLastResponse = errors.New("net/http: use last response")
```
ErrUseLastResponse can be returned by Client.CheckRedirect hooks to
control how redirects are processed. If returned, the next request
is not sent and the most recent response is returned with its body
unclosed.

## <a name="CanonicalHeaderKey">func</a> [CanonicalHeaderKey](./header.go#L173)
``` go
func CanonicalHeaderKey(s string) string
```
CanonicalHeaderKey returns the canonical format of the
header key s. The canonicalization converts the first
letter and any letter following a hyphen to upper case;
the rest are converted to lowercase. For example, the
canonical key for "accept-encoding" is "Accept-Encoding".
If s contains a space or invalid header field bytes, it is
returned without modifications.

## <a name="DetectContentType">func</a> [DetectContentType](./sniff.go#L21)
``` go
func DetectContentType(data []byte) string
```
DetectContentType implements the algorithm described
at <a href="http://mimesniff.spec.whatwg.org/">http://mimesniff.spec.whatwg.org/</a> to determine the
Content-Type of the given data. It considers at most the
first 512 bytes of data. DetectContentType always returns
a valid MIME type: if it cannot determine a more specific one, it
returns "application/octet-stream".

## <a name="Error">func</a> [Error](./server.go#L1735)
``` go
func Error(w ResponseWriter, error string, code int)
```
Error replies to the request with the specified error message and HTTP code.
It does not otherwise end the request; the caller should ensure no further
writes are done to w.
The error message should be plain text.

## <a name="Handle">func</a> [Handle](./server.go#L2076)
``` go
func Handle(pattern string, handler Handler)
```
Handle registers the handler for the given pattern
in the DefaultServeMux.
The documentation for ServeMux explains how patterns are matched.

## <a name="HandleFunc">func</a> [HandleFunc](./server.go#L2081)
``` go
func HandleFunc(pattern string, handler func(ResponseWriter, *Request))
```
HandleFunc registers the handler function for the given pattern
in the DefaultServeMux.
The documentation for ServeMux explains how patterns are matched.

## <a name="ListenAndServe">func</a> [ListenAndServe](./server.go#L2349)
``` go
func ListenAndServe(addr string, handler Handler) error
```
ListenAndServe listens on the TCP network address addr
and then calls Serve with handler to handle requests
on incoming connections.
Accepted connections are configured to enable TCP keep-alives.
Handler is typically nil, in which case the DefaultServeMux is
used.

A trivial example server is:

	package main
	
	import (
		"io"
		"net/http"
		"log"
	)
	
	// hello world, the web server
	func HelloServer(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "hello, world!\n")
	}
	
	func main() {
		http.HandleFunc("/hello", HelloServer)
		log.Fatal(http.ListenAndServe(":12345", nil))
	}

ListenAndServe always returns a non-nil error.

## <a name="ListenAndServeTLS">func</a> [ListenAndServeTLS](./server.go#L2382)
``` go
func ListenAndServeTLS(addr, certFile, keyFile string, handler Handler) error
```
ListenAndServeTLS acts identically to ListenAndServe, except that it
expects HTTPS connections. Additionally, files containing a certificate and
matching private key for the server must be provided. If the certificate
is signed by a certificate authority, the certFile should be the concatenation
of the server's certificate, any intermediates, and the CA's certificate.

A trivial example server is:

	import (
		"log"
		"net/http"
	)
	
	func handler(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("This is an example server.\n"))
	}
	
	func main() {
		http.HandleFunc("/", handler)
		log.Printf("About to listen on 10443. Go to <a href="https://127.0.0.1:10443/">https://127.0.0.1:10443/</a>")
		err := http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil)
		log.Fatal(err)
	}

One can use generate_cert.go in crypto/tls to generate cert.pem and key.pem.

ListenAndServeTLS always returns a non-nil error.

## <a name="MaxBytesReader">func</a> [MaxBytesReader](./request.go#L888)
``` go
func MaxBytesReader(w ResponseWriter, r io.ReadCloser, n int64) io.ReadCloser
```
MaxBytesReader is similar to io.LimitReader but is intended for
limiting the size of incoming request bodies. In contrast to
io.LimitReader, MaxBytesReader's result is a ReadCloser, returns a
non-EOF error for a Read beyond the limit, and closes the
underlying reader when its Close method is called.

MaxBytesReader prevents clients from accidentally or maliciously
sending a large request and wasting server resources.

## <a name="NotFound">func</a> [NotFound](./server.go#L1743)
``` go
func NotFound(w ResponseWriter, r *Request)
```
NotFound replies to the request with an HTTP 404 not found error.

## <a name="ParseHTTPVersion">func</a> [ParseHTTPVersion](./request.go#L611)
``` go
func ParseHTTPVersion(vers string) (major, minor int, ok bool)
```
ParseHTTPVersion parses a HTTP version string.
"HTTP/1.0" returns (1, 0, true).

## <a name="ParseTime">func</a> [ParseTime](./header.go#L79)
``` go
func ParseTime(text string) (t time.Time, err error)
```
ParseTime parses a time header (such as the Date: header),
trying each of the three formats allowed by HTTP/1.1:
TimeFormat, time.RFC850, and time.ANSIC.

## <a name="ProxyFromEnvironment">func</a> [ProxyFromEnvironment](./transport.go#L247)
``` go
func ProxyFromEnvironment(req *Request) (*url.URL, error)
```
ProxyFromEnvironment returns the URL of the proxy to use for a
given request, as indicated by the environment variables
HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or the lowercase versions
thereof). HTTPS_PROXY takes precedence over HTTP_PROXY for https
requests.

The environment values may be either a complete URL or a
"host[:port]", in which case the "http" scheme is assumed.
An error is returned if the value is a different form.

A nil URL and nil error are returned if no proxy is defined in the
environment, or a proxy should not be used for the given request,
as defined by NO_PROXY.

As a special case, if req.URL.Host is "localhost" (with or without
a port number), then a nil URL and nil error will be returned.

## <a name="ProxyURL">func</a> [ProxyURL](./transport.go#L281)
``` go
func ProxyURL(fixedURL *url.URL) func(*Request) (*url.URL, error)
```
ProxyURL returns a proxy function (for use in a Transport)
that always returns the same URL.

## <a name="Redirect">func</a> [Redirect](./server.go#L1773)
``` go
func Redirect(w ResponseWriter, r *Request, urlStr string, code int)
```
Redirect replies to the request with a redirect to url,
which may be a path relative to the request path.

The provided code should be in the 3xx range and is usually
StatusMovedPermanently, StatusFound or StatusSeeOther.

## <a name="Serve">func</a> [Serve](./server.go#L2089)
``` go
func Serve(l net.Listener, handler Handler) error
```
Serve accepts incoming HTTP connections on the listener l,
creating a new service goroutine for each. The service goroutines
read requests and then call handler to reply to them.
Handler is typically nil, in which case the DefaultServeMux is used.

## <a name="ServeContent">func</a> [ServeContent](./fs.go#L122)
``` go
func ServeContent(w ResponseWriter, req *Request, name string, modtime time.Time, content io.ReadSeeker)
```
ServeContent replies to the request using the content in the
provided ReadSeeker. The main benefit of ServeContent over io.Copy
is that it handles Range requests properly, sets the MIME type, and
handles If-Modified-Since requests.

If the response's Content-Type header is not set, ServeContent
first tries to deduce the type from name's file extension and,
if that fails, falls back to reading the first block of the content
and passing it to DetectContentType.
The name is otherwise unused; in particular it can be empty and is
never sent in the response.

If modtime is not the zero time or Unix epoch, ServeContent
includes it in a Last-Modified header in the response. If the
request includes an If-Modified-Since header, ServeContent uses
modtime to decide whether the content needs to be sent at all.

The content's Seek method must work: ServeContent uses
a seek to the end of the content to determine its size.

If the caller has set w's ETag header, ServeContent uses it to
handle requests using If-Range and If-None-Match.

Note that *os.File implements the io.ReadSeeker interface.

## <a name="ServeFile">func</a> [ServeFile](./fs.go#L473)
``` go
func ServeFile(w ResponseWriter, r *Request, name string)
```
ServeFile replies to the request with the contents of the named
file or directory.

If the provided file or directory name is a relative path, it is
interpreted relative to the current directory and may ascend to parent
directories. If the provided name is constructed from user input, it
should be sanitized before calling ServeFile. As a precaution, ServeFile
will reject requests where r.URL.Path contains a ".." path element.

As a special case, ServeFile redirects any request where r.URL.Path
ends in "/index.html" to the same path, without the final
"index.html". To avoid such redirects either modify the path or
use ServeContent.

## <a name="SetCookie">func</a> [SetCookie](./cookie.go#L130)
``` go
func SetCookie(w ResponseWriter, cookie *Cookie)
```
SetCookie adds a Set-Cookie header to the provided ResponseWriter's headers.
The provided cookie must have a valid Name. Invalid cookies may be
silently dropped.

## <a name="StatusText">func</a> [StatusText](./status.go#L144)
``` go
func StatusText(code int) string
```
StatusText returns a text for the HTTP status code. It returns the empty
string if the code is unknown.

## <a name="Client">type</a> [Client](./client.go#L36-L81)
``` go
type Client struct {
    // Transport specifies the mechanism by which individual
    // HTTP requests are made.
    // If nil, DefaultTransport is used.
    Transport RoundTripper

    // CheckRedirect specifies the policy for handling redirects.
    // If CheckRedirect is not nil, the client calls it before
    // following an HTTP redirect. The arguments req and via are
    // the upcoming request and the requests made already, oldest
    // first. If CheckRedirect returns an error, the Client's Get
    // method returns both the previous Response (with its Body
    // closed) and CheckRedirect's error (wrapped in a url.Error)
    // instead of issuing the Request req.
    // As a special case, if CheckRedirect returns ErrUseLastResponse,
    // then the most recent response is returned with its body
    // unclosed, along with a nil error.
    //
    // If CheckRedirect is nil, the Client uses its default policy,
    // which is to stop after 10 consecutive requests.
    CheckRedirect func(req *Request, via []*Request) error

    // Jar specifies the cookie jar.
    // If Jar is nil, cookies are not sent in requests and ignored
    // in responses.
    Jar CookieJar

    // Timeout specifies a time limit for requests made by this
    // Client. The timeout includes connection time, any
    // redirects, and reading the response body. The timer remains
    // running after Get, Head, Post, or Do return and will
    // interrupt reading of the Response.Body.
    //
    // A Timeout of zero means no timeout.
    //
    // The Client cancels requests to the underlying Transport
    // using the Request.Cancel mechanism. Requests passed
    // to Client.Do may still set Request.Cancel; both will
    // cancel the request.
    //
    // For compatibility, the Client will also use the deprecated
    // CancelRequest method on Transport if found. New
    // RoundTripper implementations should use Request.Cancel
    // instead of implementing CancelRequest.
    Timeout time.Duration
}
```
A Client is an HTTP client. Its zero value (DefaultClient) is a
usable client that uses DefaultTransport.

The Client's Transport typically has internal state (cached TCP
connections), so Clients should be reused instead of created as
needed. Clients are safe for concurrent use by multiple goroutines.

A Client is higher-level than a RoundTripper (such as Transport)
and additionally handles HTTP details such as cookies and
redirects.

### <a name="Client.Do">func</a> (\*Client) [Do](./client.go#L181)
``` go
func (c *Client) Do(req *Request) (*Response, error)
```
Do sends an HTTP request and returns an HTTP response, following
policy (such as redirects, cookies, auth) as configured on the
client.

An error is returned if caused by client policy (such as
CheckRedirect), or failure to speak HTTP (such as a network
connectivity problem). A non-2xx status code doesn't cause an
error.

If the returned error is nil, the Response will contain a non-nil
Body which the user is expected to close. If the Body is not
closed, the Client's underlying RoundTripper (typically Transport)
may not be able to re-use a persistent TCP connection to the server
for a subsequent "keep-alive" request.

The request Body, if non-nil, will be closed by the underlying
Transport, even on errors.

On error, any Response can be ignored. A non-nil Response with a
non-nil error only occurs when CheckRedirect fails, and even then
the returned Response.Body is already closed.

Generally Get, Post, or PostForm will be used instead of Do.

### <a name="Client.Get">func</a> (\*Client) [Get](./client.go#L413)
``` go
func (c *Client) Get(url string) (resp *Response, err error)
```
Get issues a GET to the specified URL. If the response is one of the
following redirect codes, Get follows the redirect after calling the
Client's CheckRedirect function:

	301 (Moved Permanently)
	302 (Found)
	303 (See Other)
	307 (Temporary Redirect)

An error is returned if the Client's CheckRedirect function fails
or if there was an HTTP protocol error. A non-2xx response doesn't
cause an error.

When err is nil, resp always contains a non-nil resp.Body.
Caller should close resp.Body when done reading from it.

To make a request with custom headers, use NewRequest and Client.Do.

### <a name="Client.Head">func</a> (\*Client) [Head](./client.go#L630)
``` go
func (c *Client) Head(url string) (resp *Response, err error)
```
Head issues a HEAD to the specified URL.  If the response is one of the
following redirect codes, Head follows the redirect after calling the
Client's CheckRedirect function:

	301 (Moved Permanently)
	302 (Found)
	303 (See Other)
	307 (Temporary Redirect)

### <a name="Client.Post">func</a> (\*Client) [Post](./client.go#L573)
``` go
func (c *Client) Post(url string, bodyType string, body io.Reader) (resp *Response, err error)
```
Post issues a POST to the specified URL.

Caller should close resp.Body when done reading from it.

If the provided body is an io.Closer, it is closed after the
request.

To set custom headers, use NewRequest and Client.Do.

### <a name="Client.PostForm">func</a> (\*Client) [PostForm](./client.go#L604)
``` go
func (c *Client) PostForm(url string, data url.Values) (resp *Response, err error)
```
PostForm issues a POST to the specified URL,
with data's keys and values URL-encoded as the request body.

The Content-Type header is set to application/x-www-form-urlencoded.
To set other headers, use NewRequest and DefaultClient.Do.

When err is nil, resp always contains a non-nil resp.Body.
Caller should close resp.Body when done reading from it.

## <a name="CloseNotifier">type</a> [CloseNotifier](./server.go#L167-L187)
``` go
type CloseNotifier interface {
    // CloseNotify returns a channel that receives at most a
    // single value (true) when the client connection has gone
    // away.
    //
    // CloseNotify may wait to notify until Request.Body has been
    // fully read.
    //
    // After the Handler has returned, there is no guarantee
    // that the channel receives a value.
    //
    // If the protocol is HTTP/1.1 and CloseNotify is called while
    // processing an idempotent request (such a GET) while
    // HTTP/1.1 pipelining is in use, the arrival of a subsequent
    // pipelined request may cause a value to be sent on the
    // returned channel. In practice HTTP/1.1 pipelining is not
    // enabled in browsers and not seen often in the wild. If this
    // is a problem, use HTTP/2 or only use CloseNotify on methods
    // such as POST.
    CloseNotify() <-chan bool
}
```
The CloseNotifier interface is implemented by ResponseWriters which
allow detecting when the underlying connection has gone away.

This mechanism can be used to cancel long operations on the server
if the client has disconnected before the response is ready.

## <a name="ConnState">type</a> [ConnState](./server.go#L2138)
``` go
type ConnState int
```
A ConnState represents the state of a client connection to a server.
It's used by the optional Server.ConnState hook.

``` go
const (
    // StateNew represents a new connection that is expected to
    // send a request immediately. Connections begin at this
    // state and then transition to either StateActive or
    // StateClosed.
    StateNew ConnState = iota

    // StateActive represents a connection that has read 1 or more
    // bytes of a request. The Server.ConnState hook for
    // StateActive fires before the request has entered a handler
    // and doesn't fire again until the request has been
    // handled. After the request is handled, the state
    // transitions to StateClosed, StateHijacked, or StateIdle.
    // For HTTP/2, StateActive fires on the transition from zero
    // to one active request, and only transitions away once all
    // active requests are complete. That means that ConnState
    // cannot be used to do per-request work; ConnState only notes
    // the overall state of the connection.
    StateActive

    // StateIdle represents a connection that has finished
    // handling a request and is in the keep-alive state, waiting
    // for a new request. Connections transition from StateIdle
    // to either StateActive or StateClosed.
    StateIdle

    // StateHijacked represents a hijacked connection.
    // This is a terminal state. It does not transition to StateClosed.
    StateHijacked

    // StateClosed represents a closed connection.
    // This is a terminal state. Hijacked connections do not
    // transition to StateClosed.
    StateClosed
)
```

### <a name="ConnState.String">func</a> (ConnState) [String](./server.go#L2184)
``` go
func (c ConnState) String() string
```

## <a name="Cookie">type</a> [Cookie](./cookie.go#L21-L38)
``` go
type Cookie struct {
    Name  string
    Value string

    Path       string    // optional
    Domain     string    // optional
    Expires    time.Time // optional
    RawExpires string    // for reading cookies only

    // MaxAge=0 means no 'Max-Age' attribute specified.
    // MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
    // MaxAge>0 means Max-Age attribute present and given in seconds
    MaxAge   int
    Secure   bool
    HttpOnly bool
    Raw      string
    Unparsed []string // Raw text of unparsed attribute-value pairs
}
```
A Cookie represents an HTTP cookie as sent in the Set-Cookie header of an
HTTP response or the Cookie header of an HTTP request.

See <a href="http://tools.ietf.org/html/rfc6265">http://tools.ietf.org/html/rfc6265</a> for details.

### <a name="Cookie.String">func</a> (\*Cookie) [String](./cookie.go#L140)
``` go
func (c *Cookie) String() string
```
String returns the serialization of the cookie for use in a Cookie
header (if only Name and Value are set) or a Set-Cookie response
header (if other fields are set).
If c is nil or c.Name is invalid, the empty string is returned.

## <a name="CookieJar">type</a> [CookieJar](./jar.go#L17-L27)
``` go
type CookieJar interface {
    // SetCookies handles the receipt of the cookies in a reply for the
    // given URL.  It may or may not choose to save the cookies, depending
    // on the jar's policy and implementation.
    SetCookies(u *url.URL, cookies []*Cookie)

    // Cookies returns the cookies to send in a request for the given URL.
    // It is up to the implementation to honor the standard cookie use
    // restrictions such as in RFC 6265.
    Cookies(u *url.URL) []*Cookie
}
```
A CookieJar manages storage and use of cookies in HTTP requests.

Implementations of CookieJar must be safe for concurrent use by multiple
goroutines.

The net/http/cookiejar package provides a CookieJar implementation.

## <a name="Dir">type</a> [Dir](./fs.go#L34)
``` go
type Dir string
```
A Dir implements FileSystem using the native file system restricted to a
specific directory tree.

While the FileSystem.Open method takes '/'-separated paths, a Dir's string
value is a filename on the native file system, not a URL, so it is separated
by filepath.Separator, which isn't necessarily '/'.

An empty Dir is treated as ".".

### <a name="Dir.Open">func</a> (Dir) [Open](./fs.go#L36)
``` go
func (d Dir) Open(name string) (File, error)
```

## <a name="File">type</a> [File](./fs.go#L63-L69)
``` go
type File interface {
    io.Closer
    io.Reader
    io.Seeker
    Readdir(count int) ([]os.FileInfo, error)
    Stat() (os.FileInfo, error)
}
```
A File is returned by a FileSystem's Open method and can be
served by the FileServer implementation.

The methods should behave the same as those on an *os.File.

## <a name="FileSystem">type</a> [FileSystem](./fs.go#L55-L57)
``` go
type FileSystem interface {
    Open(name string) (File, error)
}
```
A FileSystem implements access to a collection of named files.
The elements in a file path are separated by slash ('/', U+002F)
characters, regardless of host operating system convention.

## <a name="Flusher">type</a> [Flusher](./server.go#L135-L138)
``` go
type Flusher interface {
    // Flush sends any buffered data to the client.
    Flush()
}
```
The Flusher interface is implemented by ResponseWriters that allow
an HTTP handler to flush buffered data to the client.

The default HTTP/1.x and HTTP/2 ResponseWriter implementations
support Flusher, but ResponseWriter wrappers may not. Handlers
should always test for this ability at runtime.

Note that even for ResponseWriters that support Flush,
if the client is connected through an HTTP proxy,
the buffered data may not reach the client until the response
completes.

## <a name="Handler">type</a> [Handler](./server.go#L77-L79)
``` go
type Handler interface {
    ServeHTTP(ResponseWriter, *Request)
}
```
A Handler responds to an HTTP request.

ServeHTTP should write reply headers and data to the ResponseWriter
and then return. Returning signals that the request is finished; it
is not valid to use the ResponseWriter or read from the
Request.Body after or concurrently with the completion of the
ServeHTTP call.

Depending on the HTTP client software, HTTP protocol version, and
any intermediaries between the client and the Go server, it may not
be possible to read from the Request.Body after writing to the
ResponseWriter. Cautious handlers should read the Request.Body
first, and then reply.

Except for reading the body, handlers should not modify the
provided Request.

If ServeHTTP panics, the server (the caller of ServeHTTP) assumes
that the effect of the panic was isolated to the active request.
It recovers the panic, logs a stack trace to the server error log,
and hangs up the connection.

### <a name="FileServer">func</a> [FileServer](./fs.go#L516)
``` go
func FileServer(root FileSystem) Handler
```
FileServer returns a handler that serves HTTP requests
with the contents of the file system rooted at root.

To use the operating system's file system implementation,
use http.Dir:

	http.Handle("/", http.FileServer(http.Dir("/tmp")))

As a special case, the returned file server redirects any request
ending in "/index.html" to the same path, without the final
"index.html".

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
// Simple static webserver:
	log.Fatal(http.ListenAndServe(":8080", http.FileServer(http.Dir("/usr/share/doc"))))
```

</details>

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
// To serve a directory on disk (/tmp) under an alternate URL
	// path (/tmpfiles/), use StripPrefix to modify the request
	// URL's path before the FileServer sees it:
	http.Handle("/tmpfiles/", http.StripPrefix("/tmpfiles/", http.FileServer(http.Dir("/tmp"))))
```

</details>
### <a name="NotFoundHandler">func</a> [NotFoundHandler](./server.go#L1747)
``` go
func NotFoundHandler() Handler
```
NotFoundHandler returns a simple request handler
that replies to each request with a ``404 page not found'' reply.

### <a name="RedirectHandler">func</a> [RedirectHandler](./server.go#L1861)
``` go
func RedirectHandler(url string, code int) Handler
```
RedirectHandler returns a request handler that redirects
each request it receives to the given url using the given
status code.

The provided code should be in the 3xx range and is usually
StatusMovedPermanently, StatusFound or StatusSeeOther.

### <a name="StripPrefix">func</a> [StripPrefix](./server.go#L1754)
``` go
func StripPrefix(prefix string, h Handler) Handler
```
StripPrefix returns a handler that serves HTTP requests
by removing the given prefix from the request URL's Path
and invoking the handler h. StripPrefix handles a
request for a path that doesn't begin with prefix by
replying with an HTTP 404 not found error.

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
// To serve a directory on disk (/tmp) under an alternate URL
	// path (/tmpfiles/), use StripPrefix to modify the request
	// URL's path before the FileServer sees it:
	http.Handle("/tmpfiles/", http.StripPrefix("/tmpfiles/", http.FileServer(http.Dir("/tmp"))))
```

</details>
### <a name="TimeoutHandler">func</a> [TimeoutHandler](./server.go#L2489)
``` go
func TimeoutHandler(h Handler, dt time.Duration, msg string) Handler
```
TimeoutHandler returns a Handler that runs h with the given time limit.

The new Handler calls h.ServeHTTP to handle each request, but if a
call runs for longer than its time limit, the handler responds with
a 503 Service Unavailable error and the given message in its body.
(If msg is empty, a suitable default message will be sent.)
After such a timeout, writes by h to its ResponseWriter will return
ErrHandlerTimeout.

TimeoutHandler buffers all Handler writes to memory and does not
support the Hijacker or Flusher interfaces.

## <a name="HandlerFunc">type</a> [HandlerFunc](./server.go#L1722)
``` go
type HandlerFunc func(ResponseWriter, *Request)
```
The HandlerFunc type is an adapter to allow the use of
ordinary functions as HTTP handlers. If f is a function
with the appropriate signature, HandlerFunc(f) is a
Handler that calls f.

### <a name="HandlerFunc.ServeHTTP">func</a> (HandlerFunc) [ServeHTTP](./server.go#L1725)
``` go
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request)
```
ServeHTTP calls f(w, r).

## <a name="Header">type</a> [Header](./header.go#L19)
``` go
type Header map[string][]string
```
A Header represents the key-value pairs in an HTTP header.

### <a name="Header.Add">func</a> (Header) [Add](./header.go#L23)
``` go
func (h Header) Add(key, value string)
```
Add adds the key, value pair to the header.
It appends to any existing values associated with key.

### <a name="Header.Del">func</a> (Header) [Del](./header.go#L51)
``` go
func (h Header) Del(key string)
```
Del deletes the values associated with key.

### <a name="Header.Get">func</a> (Header) [Get](./header.go#L38)
``` go
func (h Header) Get(key string) string
```
Get gets the first value associated with the given key.
If there are no values associated with the key, Get returns "".
To access multiple values of a key, access the map directly
with CanonicalHeaderKey.

### <a name="Header.Set">func</a> (Header) [Set](./header.go#L30)
``` go
func (h Header) Set(key, value string)
```
Set sets the header entries associated with key to
the single element value. It replaces any existing
values associated with key.

### <a name="Header.Write">func</a> (Header) [Write](./header.go#L56)
``` go
func (h Header) Write(w io.Writer) error
```
Write writes a header in wire format.

### <a name="Header.WriteSubset">func</a> (Header) [WriteSubset](./header.go#L145)
``` go
func (h Header) WriteSubset(w io.Writer, exclude map[string]bool) error
```
WriteSubset writes a header in wire format.
If exclude is not nil, keys where exclude[key] == true are not written.

## <a name="Hijacker">type</a> [Hijacker](./server.go#L147-L160)
``` go
type Hijacker interface {
    // Hijack lets the caller take over the connection.
    // After a call to Hijack(), the HTTP server library
    // will not do anything else with the connection.
    //
    // It becomes the caller's responsibility to manage
    // and close the connection.
    //
    // The returned net.Conn may have read or write deadlines
    // already set, depending on the configuration of the
    // Server. It is the caller's responsibility to set
    // or clear those deadlines as needed.
    Hijack() (net.Conn, *bufio.ReadWriter, error)
}
```
The Hijacker interface is implemented by ResponseWriters that allow
an HTTP handler to take over the connection.

The default ResponseWriter for HTTP/1.x connections supports
Hijacker, but HTTP/2 connections intentionally do not.
ResponseWriter wrappers may also not support Hijacker. Handlers
should always test for this ability at runtime.

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
http.HandleFunc("/hijack", func(w http.ResponseWriter, r *http.Request) {
	    hj, ok := w.(http.Hijacker)
	    if !ok {
	        http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
	        return
	    }
	    conn, bufrw, err := hj.Hijack()
	    if err != nil {
	        http.Error(w, err.Error(), http.StatusInternalServerError)
	        return
	    }
	    // Don't forget to close the connection:
	    defer conn.Close()
	    bufrw.WriteString("Now we're speaking raw TCP. Say hi: ")
	    bufrw.Flush()
	    s, err := bufrw.ReadString('\n')
	    if err != nil {
	        log.Printf("error reading string: %v", err)
	        return
	    }
	    fmt.Fprintf(bufrw, "You said: %q\nBye.\n", s)
	    bufrw.Flush()
	})
```

</details>

## <a name="ProtocolError">type</a> [ProtocolError](./request.go#L38-L40)
``` go
type ProtocolError struct {
    ErrorString string
}
```
HTTP request parsing errors.

### <a name="ProtocolError.Error">func</a> (\*ProtocolError) [Error](./request.go#L42)
``` go
func (err *ProtocolError) Error() string
```

## <a name="Request">type</a> [Request](./request.go#L76-L268)
``` go
type Request struct {
    // Method specifies the HTTP method (GET, POST, PUT, etc.).
    // For client requests an empty string means GET.
    Method string

    // URL specifies either the URI being requested (for server
    // requests) or the URL to access (for client requests).
    //
    // For server requests the URL is parsed from the URI
    // supplied on the Request-Line as stored in RequestURI.  For
    // most requests, fields other than Path and RawQuery will be
    // empty. (See RFC 2616, Section 5.1.2)
    //
    // For client requests, the URL's Host specifies the server to
    // connect to, while the Request's Host field optionally
    // specifies the Host header value to send in the HTTP
    // request.
    URL *url.URL

    // The protocol version for incoming server requests.
    //
    // For client requests these fields are ignored. The HTTP
    // client code always uses either HTTP/1.1 or HTTP/2.
    // See the docs on Transport for details.
    Proto      string // "HTTP/1.0"
    ProtoMajor int    // 1
    ProtoMinor int    // 0

    // Header contains the request header fields either received
    // by the server or to be sent by the client.
    //
    // If a server received a request with header lines,
    //
    //	Host: example.com
    //	accept-encoding: gzip, deflate
    //	Accept-Language: en-us
    //	fOO: Bar
    //	foo: two
    //
    // then
    //
    //	Header = map[string][]string{
    //		"Accept-Encoding": {"gzip, deflate"},
    //		"Accept-Language": {"en-us"},
    //		"Foo": {"Bar", "two"},
    //	}
    //
    // For incoming requests, the Host header is promoted to the
    // Request.Host field and removed from the Header map.
    //
    // HTTP defines that header names are case-insensitive. The
    // request parser implements this by using CanonicalHeaderKey,
    // making the first character and any characters following a
    // hyphen uppercase and the rest lowercase.
    //
    // For client requests, certain headers such as Content-Length
    // and Connection are automatically written when needed and
    // values in Header may be ignored. See the documentation
    // for the Request.Write method.
    Header Header

    // Body is the request's body.
    //
    // For client requests a nil body means the request has no
    // body, such as a GET request. The HTTP Client's Transport
    // is responsible for calling the Close method.
    //
    // For server requests the Request Body is always non-nil
    // but will return EOF immediately when no body is present.
    // The Server will close the request body. The ServeHTTP
    // Handler does not need to.
    Body io.ReadCloser

    // ContentLength records the length of the associated content.
    // The value -1 indicates that the length is unknown.
    // Values >= 0 indicate that the given number of bytes may
    // be read from Body.
    // For client requests, a value of 0 means unknown if Body is not nil.
    ContentLength int64

    // TransferEncoding lists the transfer encodings from outermost to
    // innermost. An empty list denotes the "identity" encoding.
    // TransferEncoding can usually be ignored; chunked encoding is
    // automatically added and removed as necessary when sending and
    // receiving requests.
    TransferEncoding []string

    // Close indicates whether to close the connection after
    // replying to this request (for servers) or after sending this
    // request and reading its response (for clients).
    //
    // For server requests, the HTTP server handles this automatically
    // and this field is not needed by Handlers.
    //
    // For client requests, setting this field prevents re-use of
    // TCP connections between requests to the same hosts, as if
    // Transport.DisableKeepAlives were set.
    Close bool

    // For server requests Host specifies the host on which the
    // URL is sought. Per RFC 2616, this is either the value of
    // the "Host" header or the host name given in the URL itself.
    // It may be of the form "host:port".
    //
    // For client requests Host optionally overrides the Host
    // header to send. If empty, the Request.Write method uses
    // the value of URL.Host.
    Host string

    // Form contains the parsed form data, including both the URL
    // field's query parameters and the POST or PUT form data.
    // This field is only available after ParseForm is called.
    // The HTTP client ignores Form and uses Body instead.
    Form url.Values

    // PostForm contains the parsed form data from POST, PATCH,
    // or PUT body parameters.
    //
    // This field is only available after ParseForm is called.
    // The HTTP client ignores PostForm and uses Body instead.
    PostForm url.Values

    // MultipartForm is the parsed multipart form, including file uploads.
    // This field is only available after ParseMultipartForm is called.
    // The HTTP client ignores MultipartForm and uses Body instead.
    MultipartForm *multipart.Form

    // Trailer specifies additional headers that are sent after the request
    // body.
    //
    // For server requests the Trailer map initially contains only the
    // trailer keys, with nil values. (The client declares which trailers it
    // will later send.)  While the handler is reading from Body, it must
    // not reference Trailer. After reading from Body returns EOF, Trailer
    // can be read again and will contain non-nil values, if they were sent
    // by the client.
    //
    // For client requests Trailer must be initialized to a map containing
    // the trailer keys to later send. The values may be nil or their final
    // values. The ContentLength must be 0 or -1, to send a chunked request.
    // After the HTTP request is sent the map values can be updated while
    // the request body is read. Once the body returns EOF, the caller must
    // not mutate Trailer.
    //
    // Few HTTP clients, servers, or proxies support HTTP trailers.
    Trailer Header

    // RemoteAddr allows HTTP servers and other software to record
    // the network address that sent the request, usually for
    // logging. This field is not filled in by ReadRequest and
    // has no defined format. The HTTP server in this package
    // sets RemoteAddr to an "IP:port" address before invoking a
    // handler.
    // This field is ignored by the HTTP client.
    RemoteAddr string

    // RequestURI is the unmodified Request-URI of the
    // Request-Line (RFC 2616, Section 5.1) as sent by the client
    // to a server. Usually the URL field should be used instead.
    // It is an error to set this field in an HTTP client request.
    RequestURI string

    // TLS allows HTTP servers and other software to record
    // information about the TLS connection on which the request
    // was received. This field is not filled in by ReadRequest.
    // The HTTP server in this package sets the field for
    // TLS-enabled connections before invoking a handler;
    // otherwise it leaves the field nil.
    // This field is ignored by the HTTP client.
    TLS *tls.ConnectionState

    // Cancel is an optional channel whose closure indicates that the client
    // request should be regarded as canceled. Not all implementations of
    // RoundTripper may support Cancel.
    //
    // For server requests, this field is not applicable.
    //
    // Deprecated: Use the Context and WithContext methods
    // instead. If a Request's Cancel field and context are both
    // set, it is undefined whether Cancel is respected.
    Cancel <-chan struct{}

    // Response is the redirect response which caused this request
    // to be created. This field is only populated during client
    // redirects.
    Response *Response
    // contains filtered or unexported fields
}
```
A Request represents an HTTP request received by a server
or to be sent by a client.

The field semantics differ slightly between client and server
usage. In addition to the notes on the fields below, see the
documentation for Request.Write and RoundTripper.

### <a name="NewRequest">func</a> [NewRequest](./request.go#L666)
``` go
func NewRequest(method, urlStr string, body io.Reader) (*Request, error)
```
NewRequest returns a new Request given a method, URL, and optional body.

If the provided body is also an io.Closer, the returned
Request.Body is set to body and will be closed by the Client
methods Do, Post, and PostForm, and Transport.RoundTrip.

NewRequest returns a Request suitable for use with Client.Do or
Transport.RoundTrip.
To create a request for use with testing a Server Handler use either
ReadRequest or manually update the Request fields. See the Request
type's documentation for the difference between inbound and outbound
request fields.

### <a name="ReadRequest">func</a> [ReadRequest](./request.go#L777)
``` go
func ReadRequest(b *bufio.Reader) (*Request, error)
```
ReadRequest reads and parses an incoming request from b.

### <a name="Request.AddCookie">func</a> (\*Request) [AddCookie](./request.go#L333)
``` go
func (r *Request) AddCookie(c *Cookie)
```
AddCookie adds a cookie to the request. Per RFC 6265 section 5.4,
AddCookie does not attach more than one Cookie header field. That
means all cookies, if any, are written into the same line,
separated by semicolon.

### <a name="Request.BasicAuth">func</a> (\*Request) [BasicAuth](./request.go#L713)
``` go
func (r *Request) BasicAuth() (username, password string, ok bool)
```
BasicAuth returns the username and password provided in the request's
Authorization header, if the request uses HTTP Basic Authentication.
See RFC 2617, Section 2.

### <a name="Request.Context">func</a> (\*Request) [Context](./request.go#L281)
``` go
func (r *Request) Context() context.Context
```
Context returns the request's context. To change the context, use
WithContext.

The returned context is always non-nil; it defaults to the
background context.

For outgoing client requests, the context controls cancelation.

For incoming server requests, the context is canceled when the
ServeHTTP method returns. For its associated values, see
ServerContextKey and LocalAddrContextKey.

### <a name="Request.Cookie">func</a> (\*Request) [Cookie](./request.go#L322)
``` go
func (r *Request) Cookie(name string) (*Cookie, error)
```
Cookie returns the named cookie provided in the request or
ErrNoCookie if not found.

### <a name="Request.Cookies">func</a> (\*Request) [Cookies](./request.go#L313)
``` go
func (r *Request) Cookies() []*Cookie
```
Cookies parses and returns the HTTP cookies sent with the request.

### <a name="Request.FormFile">func</a> (\*Request) [FormFile](./request.go#L1128)
``` go
func (r *Request) FormFile(key string) (multipart.File, *multipart.FileHeader, error)
```
FormFile returns the first file for the provided form key.
FormFile calls ParseMultipartForm and ParseForm if necessary.

### <a name="Request.FormValue">func</a> (\*Request) [FormValue](./request.go#L1101)
``` go
func (r *Request) FormValue(key string) string
```
FormValue returns the first value for the named component of the query.
POST and PUT body parameters take precedence over URL query string values.
FormValue calls ParseMultipartForm and ParseForm if necessary and ignores
any errors returned by these functions.
If key is not present, FormValue returns the empty string.
To access multiple values of the same key, call ParseForm and
then inspect Request.Form directly.

### <a name="Request.MultipartReader">func</a> (\*Request) [MultipartReader](./request.go#L366)
``` go
func (r *Request) MultipartReader() (*multipart.Reader, error)
```
MultipartReader returns a MIME multipart reader if this is a
multipart/form-data POST request, else returns nil and an error.
Use this function instead of ParseMultipartForm to
process the request body as a stream.

### <a name="Request.ParseForm">func</a> (\*Request) [ParseForm](./request.go#L1015)
``` go
func (r *Request) ParseForm() error
```
ParseForm parses the raw query from the URL and updates r.Form.

For POST or PUT requests, it also parses the request body as a form and
put the results into both r.PostForm and r.Form.
POST and PUT body parameters take precedence over URL query string values
in r.Form.

If the request Body's size has not already been limited by MaxBytesReader,
the size is capped at 10MB.

ParseMultipartForm calls ParseForm automatically.
It is idempotent.

### <a name="Request.ParseMultipartForm">func</a> (\*Request) [ParseMultipartForm](./request.go#L1056)
``` go
func (r *Request) ParseMultipartForm(maxMemory int64) error
```
ParseMultipartForm parses a request body as multipart/form-data.
The whole request body is parsed and up to a total of maxMemory bytes of
its file parts are stored in memory, with the remainder stored on
disk in temporary files.
ParseMultipartForm calls ParseForm if necessary.
After one call to ParseMultipartForm, subsequent calls have no effect.

### <a name="Request.PostFormValue">func</a> (\*Request) [PostFormValue](./request.go#L1116)
``` go
func (r *Request) PostFormValue(key string) string
```
PostFormValue returns the first value for the named component of the POST
or PUT request body. URL query parameters are ignored.
PostFormValue calls ParseMultipartForm and ParseForm if necessary and ignores
any errors returned by these functions.
If key is not present, PostFormValue returns the empty string.

### <a name="Request.ProtoAtLeast">func</a> (\*Request) [ProtoAtLeast](./request.go#L302)
``` go
func (r *Request) ProtoAtLeast(major, minor int) bool
```
ProtoAtLeast reports whether the HTTP protocol used
in the request is at least major.minor.

### <a name="Request.Referer">func</a> (\*Request) [Referer](./request.go#L350)
``` go
func (r *Request) Referer() string
```
Referer returns the referring URL, if sent in the request.

Referer is misspelled as in the request itself, a mistake from the
earliest days of HTTP.  This value can also be fetched from the
Header map as Header["Referer"]; the benefit of making it available
as a method is that the compiler can diagnose programs that use the
alternate (correct English) spelling req.Referrer() but cannot
diagnose programs that use Header["Referrer"].

### <a name="Request.SetBasicAuth">func</a> (\*Request) [SetBasicAuth](./request.go#L745)
``` go
func (r *Request) SetBasicAuth(username, password string)
```
SetBasicAuth sets the request's Authorization header to use HTTP
Basic Authentication with the provided username and password.

With HTTP Basic Authentication the provided username and password
are not encrypted.

### <a name="Request.UserAgent">func</a> (\*Request) [UserAgent](./request.go#L308)
``` go
func (r *Request) UserAgent() string
```
UserAgent returns the client's User-Agent, if sent in the request.

### <a name="Request.WithContext">func</a> (\*Request) [WithContext](./request.go#L290)
``` go
func (r *Request) WithContext(ctx context.Context) *Request
```
WithContext returns a shallow copy of r with its context changed
to ctx. The provided ctx must be non-nil.

### <a name="Request.Write">func</a> (\*Request) [Write](./request.go#L426)
``` go
func (r *Request) Write(w io.Writer) error
```
Write writes an HTTP/1.1 request, which is the header and body, in wire format.
This method consults the following fields of the request:

	Host
	URL
	Method (defaults to "GET")
	Header
	ContentLength
	TransferEncoding
	Body

If Body is present, Content-Length is <= 0 and TransferEncoding
hasn't been set to "identity", Write adds "Transfer-Encoding:
chunked" to the header. Body is closed after it is sent.

### <a name="Request.WriteProxy">func</a> (\*Request) [WriteProxy](./request.go#L436)
``` go
func (r *Request) WriteProxy(w io.Writer) error
```
WriteProxy is like Write but writes the request in the form
expected by an HTTP proxy. In particular, WriteProxy writes the
initial Request-URI line of the request with an absolute URI, per
section 5.1.2 of RFC 2616, including the scheme and host.
In either case, WriteProxy also writes a Host header, using
either r.Host or r.URL.Host.

## <a name="Response">type</a> [Response](./response.go#L30-L109)
``` go
type Response struct {
    Status     string // e.g. "200 OK"
    StatusCode int    // e.g. 200
    Proto      string // e.g. "HTTP/1.0"
    ProtoMajor int    // e.g. 1
    ProtoMinor int    // e.g. 0

    // Header maps header keys to values. If the response had multiple
    // headers with the same key, they may be concatenated, with comma
    // delimiters.  (Section 4.2 of RFC 2616 requires that multiple headers
    // be semantically equivalent to a comma-delimited sequence.) Values
    // duplicated by other fields in this struct (e.g., ContentLength) are
    // omitted from Header.
    //
    // Keys in the map are canonicalized (see CanonicalHeaderKey).
    Header Header

    // Body represents the response body.
    //
    // The http Client and Transport guarantee that Body is always
    // non-nil, even on responses without a body or responses with
    // a zero-length body. It is the caller's responsibility to
    // close Body. The default HTTP client's Transport does not
    // attempt to reuse HTTP/1.0 or HTTP/1.1 TCP connections
    // ("keep-alive") unless the Body is read to completion and is
    // closed.
    //
    // The Body is automatically dechunked if the server replied
    // with a "chunked" Transfer-Encoding.
    Body io.ReadCloser

    // ContentLength records the length of the associated content. The
    // value -1 indicates that the length is unknown. Unless Request.Method
    // is "HEAD", values >= 0 indicate that the given number of bytes may
    // be read from Body.
    ContentLength int64

    // Contains transfer encodings from outer-most to inner-most. Value is
    // nil, means that "identity" encoding is used.
    TransferEncoding []string

    // Close records whether the header directed that the connection be
    // closed after reading Body. The value is advice for clients: neither
    // ReadResponse nor Response.Write ever closes a connection.
    Close bool

    // Uncompressed reports whether the response was sent compressed but
    // was decompressed by the http package. When true, reading from
    // Body yields the uncompressed content instead of the compressed
    // content actually set from the server, ContentLength is set to -1,
    // and the "Content-Length" and "Content-Encoding" fields are deleted
    // from the responseHeader. To get the original response from
    // the server, set Transport.DisableCompression to true.
    Uncompressed bool

    // Trailer maps trailer keys to values in the same
    // format as Header.
    //
    // The Trailer initially contains only nil values, one for
    // each key specified in the server's "Trailer" header
    // value. Those values are not added to Header.
    //
    // Trailer must not be accessed concurrently with Read calls
    // on the Body.
    //
    // After Body.Read has returned io.EOF, Trailer will contain
    // any trailer values sent by the server.
    Trailer Header

    // Request is the request that was sent to obtain this Response.
    // Request's Body is nil (having already been consumed).
    // This is only populated for Client requests.
    Request *Request

    // TLS contains information about the TLS connection on which the
    // response was received. It is nil for unencrypted responses.
    // The pointer is shared between responses and should not be
    // modified.
    TLS *tls.ConnectionState
}
```
Response represents the response from an HTTP request.

### <a name="Get">func</a> [Get](./client.go#L392)
``` go
func Get(url string) (resp *Response, err error)
```
Get issues a GET to the specified URL. If the response is one of
the following redirect codes, Get follows the redirect, up to a
maximum of 10 redirects:

	301 (Moved Permanently)
	302 (Found)
	303 (See Other)
	307 (Temporary Redirect)

An error is returned if there were too many redirects or if there
was an HTTP protocol error. A non-2xx response doesn't cause an
error.

When err is nil, resp always contains a non-nil resp.Body.
Caller should close resp.Body when done reading from it.

Get is a wrapper around DefaultClient.Get.

To make a request with custom headers, use NewRequest and
DefaultClient.Do.

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
res, err := http.Get("http://www.google.com/robots.txt")
	if err != nil {
	    log.Fatal(err)
	}
	robots, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
	    log.Fatal(err)
	}
	fmt.Printf("%s", robots)
```

</details>
### <a name="Head">func</a> [Head](./client.go#L618)
``` go
func Head(url string) (resp *Response, err error)
```
Head issues a HEAD to the specified URL.  If the response is one of
the following redirect codes, Head follows the redirect, up to a
maximum of 10 redirects:

	301 (Moved Permanently)
	302 (Found)
	303 (See Other)
	307 (Temporary Redirect)

Head is a wrapper around DefaultClient.Head

### <a name="Post">func</a> [Post](./client.go#L561)
``` go
func Post(url string, bodyType string, body io.Reader) (resp *Response, err error)
```
Post issues a POST to the specified URL.

Caller should close resp.Body when done reading from it.

If the provided body is an io.Closer, it is closed after the
request.

Post is a wrapper around DefaultClient.Post.

To set custom headers, use NewRequest and DefaultClient.Do.

### <a name="PostForm">func</a> [PostForm](./client.go#L592)
``` go
func PostForm(url string, data url.Values) (resp *Response, err error)
```
PostForm issues a POST to the specified URL, with data's keys and
values URL-encoded as the request body.

The Content-Type header is set to application/x-www-form-urlencoded.
To set other headers, use NewRequest and DefaultClient.Do.

When err is nil, resp always contains a non-nil resp.Body.
Caller should close resp.Body when done reading from it.

PostForm is a wrapper around DefaultClient.PostForm.

### <a name="ReadResponse">func</a> [ReadResponse](./response.go#L141)
``` go
func ReadResponse(r *bufio.Reader, req *Request) (*Response, error)
```
ReadResponse reads and returns an HTTP response from r.
The req parameter optionally specifies the Request that corresponds
to this Response. If nil, a GET request is assumed.
Clients must call resp.Body.Close when finished reading resp.Body.
After that call, clients can inspect resp.Trailer to find key/value
pairs included in the response trailer.

### <a name="Response.Cookies">func</a> (\*Response) [Cookies](./response.go#L112)
``` go
func (r *Response) Cookies() []*Cookie
```
Cookies parses and returns the cookies set in the Set-Cookie headers.

### <a name="Response.Location">func</a> (\*Response) [Location](./response.go#L124)
``` go
func (r *Response) Location() (*url.URL, error)
```
Location returns the URL of the response's "Location" header,
if present. Relative redirects are resolved relative to
the Response's Request. ErrNoLocation is returned if no
Location header is present.

### <a name="Response.ProtoAtLeast">func</a> (\*Response) [ProtoAtLeast](./response.go#L211)
``` go
func (r *Response) ProtoAtLeast(major, minor int) bool
```
ProtoAtLeast reports whether the HTTP protocol used
in the response is at least major.minor.

### <a name="Response.Write">func</a> (\*Response) [Write](./response.go#L232)
``` go
func (r *Response) Write(w io.Writer) error
```
Write writes r to w in the HTTP/1.x server response format,
including the status line, headers, body, and optional trailer.

This method consults the following fields of the response r:

	StatusCode
	ProtoMajor
	ProtoMinor
	Request.Method
	TransferEncoding
	Trailer
	Body
	ContentLength
	Header, values for non-canonical keys will have unpredictable behavior

The Response Body is closed after it is sent.

## <a name="ResponseWriter">type</a> [ResponseWriter](./server.go#L86-L122)
``` go
type ResponseWriter interface {
    // Header returns the header map that will be sent by
    // WriteHeader. Changing the header after a call to
    // WriteHeader (or Write) has no effect unless the modified
    // headers were declared as trailers by setting the
    // "Trailer" header before the call to WriteHeader (see example).
    // To suppress implicit response headers, set their value to nil.
    Header() Header

    // Write writes the data to the connection as part of an HTTP reply.
    //
    // If WriteHeader has not yet been called, Write calls
    // WriteHeader(http.StatusOK) before writing the data. If the Header
    // does not contain a Content-Type line, Write adds a Content-Type set
    // to the result of passing the initial 512 bytes of written data to
    // DetectContentType.
    //
    // Depending on the HTTP protocol version and the client, calling
    // Write or WriteHeader may prevent future reads on the
    // Request.Body. For HTTP/1.x requests, handlers should read any
    // needed request body data before writing the response. Once the
    // headers have been flushed (due to either an explicit Flusher.Flush
    // call or writing enough data to trigger a flush), the request body
    // may be unavailable. For HTTP/2 requests, the Go HTTP server permits
    // handlers to continue to read the request body while concurrently
    // writing the response. However, such behavior may not be supported
    // by all HTTP/2 clients. Handlers should read before writing if
    // possible to maximize compatibility.
    Write([]byte) (int, error)

    // WriteHeader sends an HTTP response header with status code.
    // If WriteHeader is not called explicitly, the first call to Write
    // will trigger an implicit WriteHeader(http.StatusOK).
    // Thus explicit calls to WriteHeader are mainly used to
    // send error codes.
    WriteHeader(int)
}
```
A ResponseWriter interface is used by an HTTP handler to
construct an HTTP response.

A ResponseWriter may not be used after the Handler.ServeHTTP method
has returned.

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
mux := http.NewServeMux()
	mux.HandleFunc("/sendstrailers", func(w http.ResponseWriter, req *http.Request) {
	    // Before any call to WriteHeader or Write, declare
	    // the trailers you will set during the HTTP
	    // response. These three headers are actually sent in
	    // the trailer.
	    w.Header().Set("Trailer", "AtEnd1, AtEnd2")
	    w.Header().Add("Trailer", "AtEnd3")
	
	    w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	    w.WriteHeader(http.StatusOK)
	
	    w.Header().Set("AtEnd1", "value 1")
	    io.WriteString(w, "This HTTP response has both headers before this text and trailers at the end.\n")
	    w.Header().Set("AtEnd2", "value 2")
	    w.Header().Set("AtEnd3", "value 3") // These will appear as trailers.
	})
```

</details>

## <a name="RoundTripper">type</a> [RoundTripper](./client.go#L91-L114)
``` go
type RoundTripper interface {
    // RoundTrip executes a single HTTP transaction, returning
    // a Response for the provided Request.
    //
    // RoundTrip should not attempt to interpret the response. In
    // particular, RoundTrip must return err == nil if it obtained
    // a response, regardless of the response's HTTP status code.
    // A non-nil err should be reserved for failure to obtain a
    // response. Similarly, RoundTrip should not attempt to
    // handle higher-level protocol details such as redirects,
    // authentication, or cookies.
    //
    // RoundTrip should not modify the request, except for
    // consuming and closing the Request's Body.
    //
    // RoundTrip must always close the body, including on errors,
    // but depending on the implementation may do so in a separate
    // goroutine even after RoundTrip returns. This means that
    // callers wanting to reuse the body for subsequent requests
    // must arrange to wait for the Close call before doing so.
    //
    // The Request's URL and Header fields must be initialized.
    RoundTrip(*Request) (*Response, error)
}
```
RoundTripper is an interface representing the ability to execute a
single HTTP transaction, obtaining the Response for a given Request.

A RoundTripper must be safe for concurrent use by multiple
goroutines.

``` go
var DefaultTransport RoundTripper = &Transport{
    Proxy: ProxyFromEnvironment,
    DialContext: (&net.Dialer{
        Timeout:   30 * time.Second,
        KeepAlive: 30 * time.Second,
    }).DialContext,
    MaxIdleConns:          100,
    IdleConnTimeout:       90 * time.Second,
    TLSHandshakeTimeout:   10 * time.Second,
    ExpectContinueTimeout: 1 * time.Second,
}
```
DefaultTransport is the default implementation of Transport and is
used by DefaultClient. It establishes network connections as needed
and caches them for reuse by subsequent calls. It uses HTTP proxies
as directed by the $HTTP_PROXY and $NO_PROXY (or $http_proxy and
$no_proxy) environment variables.

### <a name="NewFileTransport">func</a> [NewFileTransport](./filetransport.go#L30)
``` go
func NewFileTransport(fs FileSystem) RoundTripper
```
NewFileTransport returns a new RoundTripper, serving the provided
FileSystem. The returned RoundTripper ignores the URL host in its
incoming requests, as well as most other properties of the
request.

The typical use case for NewFileTransport is to register the "file"
protocol with a Transport, as in:

	t := &http.Transport{}
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	c := &http.Client{Transport: t}
	res, err := c.Get("file:///etc/passwd")
	...

## <a name="ServeMux">type</a> [ServeMux](./server.go#L1900-L1904)
``` go
type ServeMux struct {
    // contains filtered or unexported fields
}
```
ServeMux is an HTTP request multiplexer.
It matches the URL of each incoming request against a list of registered
patterns and calls the handler for the pattern that
most closely matches the URL.

Patterns name fixed, rooted paths, like "/favicon.ico",
or rooted subtrees, like "/images/" (note the trailing slash).
Longer patterns take precedence over shorter ones, so that
if there are handlers registered for both "/images/"
and "/images/thumbnails/", the latter handler will be
called for paths beginning "/images/thumbnails/" and the
former will receive requests for any other paths in the
"/images/" subtree.

Note that since a pattern ending in a slash names a rooted subtree,
the pattern "/" matches all paths not matched by other registered
patterns, not just the URL with Path == "/".

If a subtree has been registered and a request is received naming the
subtree root without its trailing slash, ServeMux redirects that
request to the subtree root (adding the trailing slash). This behavior can
be overridden with a separate registration for the path without
the trailing slash. For example, registering "/images/" causes ServeMux
to redirect a request for "/images" to "/images/", unless "/images" has
been registered separately.

Patterns may optionally begin with a host name, restricting matches to
URLs on that host only. Host-specific patterns take precedence over
general patterns, so that a handler might register for the two patterns
"/codesearch" and "codesearch.google.com/" without also taking over
requests for "<a href="http://www.google.com/">http://www.google.com/</a>".

ServeMux also takes care of sanitizing the URL request path,
redirecting any request containing . or .. elements or repeated slashes
to an equivalent, cleaner URL.

### <a name="NewServeMux">func</a> [NewServeMux](./server.go#L1913)
``` go
func NewServeMux() *ServeMux
```
NewServeMux allocates and returns a new ServeMux.

### <a name="ServeMux.Handle">func</a> (\*ServeMux) [Handle](./server.go#L2027)
``` go
func (mux *ServeMux) Handle(pattern string, handler Handler)
```
Handle registers the handler for the given pattern.
If a handler already exists for pattern, Handle panics.

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler{})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
	    // The "/" pattern matches everything, so we need to check
	    // that we're at the root here.
	    if req.URL.Path != "/" {
	        http.NotFound(w, req)
	        return
	    }
	    fmt.Fprintf(w, "Welcome to the home page!")
	})
```

</details>

### <a name="ServeMux.HandleFunc">func</a> (\*ServeMux) [HandleFunc](./server.go#L2069)
``` go
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Request))
```
HandleFunc registers the handler function for the given pattern.

### <a name="ServeMux.Handler">func</a> (\*ServeMux) [Handler](./server.go#L1979)
``` go
func (mux *ServeMux) Handler(r *Request) (h Handler, pattern string)
```
Handler returns the handler to use for the given request,
consulting r.Method, r.Host, and r.URL.Path. It always returns
a non-nil handler. If the path is not in its canonical form, the
handler will be an internally-generated handler that redirects
to the canonical path.

Handler also returns the registered pattern that matches the
request or, in the case of internally-generated redirects,
the pattern that will match after following the redirect.

If there is no registered handler that applies to the request,
Handler returns a ``page not found'' handler and an empty pattern.

### <a name="ServeMux.ServeHTTP">func</a> (\*ServeMux) [ServeHTTP](./server.go#L2013)
``` go
func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
```
ServeHTTP dispatches the request to the handler whose
pattern most closely matches the request URL.

## <a name="Server">type</a> [Server](./server.go#L2096-L2134)
``` go
type Server struct {
    Addr         string        // TCP address to listen on, ":http" if empty
    Handler      Handler       // handler to invoke, http.DefaultServeMux if nil
    ReadTimeout  time.Duration // maximum duration before timing out read of the request
    WriteTimeout time.Duration // maximum duration before timing out write of the response
    TLSConfig    *tls.Config   // optional TLS config, used by ListenAndServeTLS

    // MaxHeaderBytes controls the maximum number of bytes the
    // server will read parsing the request header's keys and
    // values, including the request line. It does not limit the
    // size of the request body.
    // If zero, DefaultMaxHeaderBytes is used.
    MaxHeaderBytes int

    // TLSNextProto optionally specifies a function to take over
    // ownership of the provided TLS connection when an NPN/ALPN
    // protocol upgrade has occurred. The map key is the protocol
    // name negotiated. The Handler argument should be used to
    // handle HTTP requests and will initialize the Request's TLS
    // and RemoteAddr if not already set. The connection is
    // automatically closed when the function returns.
    // If TLSNextProto is nil, HTTP/2 support is enabled automatically.
    TLSNextProto map[string]func(*Server, *tls.Conn, Handler)

    // ConnState specifies an optional callback function that is
    // called when a client connection changes state. See the
    // ConnState type and associated constants for details.
    ConnState func(net.Conn, ConnState)

    // ErrorLog specifies an optional logger for errors accepting
    // connections and unexpected behavior from handlers.
    // If nil, logging goes to os.Stderr via the log package's
    // standard logger.
    ErrorLog *log.Logger
    // contains filtered or unexported fields
}
```
A Server defines parameters for running an HTTP server.
The zero value for Server is a valid configuration.

### <a name="Server.ListenAndServe">func</a> (\*Server) [ListenAndServe](./server.go#L2210)
``` go
func (srv *Server) ListenAndServe() error
```
ListenAndServe listens on the TCP network address srv.Addr and then
calls Serve to handle requests on incoming connections.
Accepted connections are configured to enable TCP keep-alives.
If srv.Addr is blank, ":http" is used.
ListenAndServe always returns a non-nil error.

### <a name="Server.ListenAndServeTLS">func</a> (\*Server) [ListenAndServeTLS](./server.go#L2401)
``` go
func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error
```
ListenAndServeTLS listens on the TCP network address srv.Addr and
then calls Serve to handle requests on incoming TLS connections.
Accepted connections are configured to enable TCP keep-alives.

Filenames containing a certificate and matching private key for the
server must be provided if neither the Server's TLSConfig.Certificates
nor TLSConfig.GetCertificate are populated. If the certificate is
signed by a certificate authority, the certFile should be the
concatenation of the server's certificate, any intermediates, and
the CA's certificate.

If srv.Addr is blank, ":https" is used.

ListenAndServeTLS always returns a non-nil error.

### <a name="Server.Serve">func</a> (\*Server) [Serve](./server.go#L2256)
``` go
func (srv *Server) Serve(l net.Listener) error
```
Serve accepts incoming connections on the Listener l, creating a
new service goroutine for each. The service goroutines read requests and
then call srv.Handler to reply to them.

For HTTP/2 support, srv.TLSConfig should be initialized to the
provided listener's TLS Config before calling Serve. If
srv.TLSConfig is non-nil and doesn't include the string "h2" in
Config.NextProtos, HTTP/2 support is not enabled.

Serve always returns a non-nil error.

### <a name="Server.SetKeepAlivesEnabled">func</a> (\*Server) [SetKeepAlivesEnabled](./server.go#L2305)
``` go
func (srv *Server) SetKeepAlivesEnabled(v bool)
```
SetKeepAlivesEnabled controls whether HTTP keep-alives are enabled.
By default, keep-alives are always enabled. Only very
resource-constrained environments or servers in the process of
shutting down should disable them.

## <a name="Transport">type</a> [Transport](./transport.go#L71-L187)
``` go
type Transport struct {

    // Proxy specifies a function to return a proxy for a given
    // Request. If the function returns a non-nil error, the
    // request is aborted with the provided error.
    // If Proxy is nil or returns a nil *URL, no proxy is used.
    Proxy func(*Request) (*url.URL, error)

    // DialContext specifies the dial function for creating unencrypted TCP connections.
    // If DialContext is nil (and the deprecated Dial below is also nil),
    // then the transport dials using package net.
    DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

    // Dial specifies the dial function for creating unencrypted TCP connections.
    //
    // Deprecated: Use DialContext instead, which allows the transport
    // to cancel dials as soon as they are no longer needed.
    // If both are set, DialContext takes priority.
    Dial func(network, addr string) (net.Conn, error)

    // DialTLS specifies an optional dial function for creating
    // TLS connections for non-proxied HTTPS requests.
    //
    // If DialTLS is nil, Dial and TLSClientConfig are used.
    //
    // If DialTLS is set, the Dial hook is not used for HTTPS
    // requests and the TLSClientConfig and TLSHandshakeTimeout
    // are ignored. The returned net.Conn is assumed to already be
    // past the TLS handshake.
    DialTLS func(network, addr string) (net.Conn, error)

    // TLSClientConfig specifies the TLS configuration to use with
    // tls.Client. If nil, the default configuration is used.
    TLSClientConfig *tls.Config

    // TLSHandshakeTimeout specifies the maximum amount of time waiting to
    // wait for a TLS handshake. Zero means no timeout.
    TLSHandshakeTimeout time.Duration

    // DisableKeepAlives, if true, prevents re-use of TCP connections
    // between different HTTP requests.
    DisableKeepAlives bool

    // DisableCompression, if true, prevents the Transport from
    // requesting compression with an "Accept-Encoding: gzip"
    // request header when the Request contains no existing
    // Accept-Encoding value. If the Transport requests gzip on
    // its own and gets a gzipped response, it's transparently
    // decoded in the Response.Body. However, if the user
    // explicitly requested gzip it is not automatically
    // uncompressed.
    DisableCompression bool

    // MaxIdleConns controls the maximum number of idle (keep-alive)
    // connections across all hosts. Zero means no limit.
    MaxIdleConns int

    // MaxIdleConnsPerHost, if non-zero, controls the maximum idle
    // (keep-alive) connections to keep per-host. If zero,
    // DefaultMaxIdleConnsPerHost is used.
    MaxIdleConnsPerHost int

    // IdleConnTimeout is the maximum amount of time an idle
    // (keep-alive) connection will remain idle before closing
    // itself.
    // Zero means no limit.
    IdleConnTimeout time.Duration

    // ResponseHeaderTimeout, if non-zero, specifies the amount of
    // time to wait for a server's response headers after fully
    // writing the request (including its body, if any). This
    // time does not include the time to read the response body.
    ResponseHeaderTimeout time.Duration

    // ExpectContinueTimeout, if non-zero, specifies the amount of
    // time to wait for a server's first response headers after fully
    // writing the request headers if the request has an
    // "Expect: 100-continue" header. Zero means no timeout.
    // This time does not include the time to send the request header.
    ExpectContinueTimeout time.Duration

    // TLSNextProto specifies how the Transport switches to an
    // alternate protocol (such as HTTP/2) after a TLS NPN/ALPN
    // protocol negotiation. If Transport dials an TLS connection
    // with a non-empty protocol name and TLSNextProto contains a
    // map entry for that key (such as "h2"), then the func is
    // called with the request's authority (such as "example.com"
    // or "example.com:1234") and the TLS connection. The function
    // must return a RoundTripper that then handles the request.
    // If TLSNextProto is nil, HTTP/2 support is enabled automatically.
    TLSNextProto map[string]func(authority string, c *tls.Conn) RoundTripper

    // MaxResponseHeaderBytes specifies a limit on how many
    // response bytes are allowed in the server's response
    // header.
    //
    // Zero means to use a default limit.
    MaxResponseHeaderBytes int64
    // contains filtered or unexported fields
}
```
Transport is an implementation of RoundTripper that supports HTTP,
HTTPS, and HTTP proxies (for either HTTP or HTTPS with CONNECT).

By default, Transport caches connections for future re-use.
This may leave many open connections when accessing many hosts.
This behavior can be managed using Transport's CloseIdleConnections method
and the MaxIdleConnsPerHost and DisableKeepAlives fields.

Transports should be reused instead of created as needed.
Transports are safe for concurrent use by multiple goroutines.

A Transport is a low-level primitive for making HTTP and HTTPS requests.
For high-level functionality, such as cookies and redirects, see Client.

Transport uses HTTP/1.1 for HTTP URLs and either HTTP/1.1 or HTTP/2
for HTTPS URLs, depending on whether the server supports HTTP/2.
See the package docs for more about HTTP/2.

### <a name="Transport.CancelRequest">func</a> (\*Transport) [CancelRequest](./transport.go#L504)
``` go
func (t *Transport) CancelRequest(req *Request)
```
CancelRequest cancels an in-flight request by closing its connection.
CancelRequest should only be called after RoundTrip has returned.

Deprecated: Use Request.WithContext to create a request with a
cancelable context instead. CancelRequest cannot cancel HTTP/2
requests.

### <a name="Transport.CloseIdleConnections">func</a> (\*Transport) [CloseIdleConnections](./transport.go#L479)
``` go
func (t *Transport) CloseIdleConnections()
```
CloseIdleConnections closes any connections which were previously
connected from previous requests but are now sitting idle in
a "keep-alive" state. It does not interrupt any connections currently
in use.

### <a name="Transport.RegisterProtocol">func</a> (\*Transport) [RegisterProtocol](./transport.go#L463)
``` go
func (t *Transport) RegisterProtocol(scheme string, rt RoundTripper)
```
RegisterProtocol registers a new protocol with scheme.
The Transport will pass requests using the given scheme to rt.
It is rt's responsibility to simulate HTTP request semantics.

RegisterProtocol can be used by other packages to provide
implementations of protocol schemes like "ftp" or "file".

If rt.RoundTrip returns ErrSkipAltProtocol, the Transport will
handle the RoundTrip itself for that one request, as if the
protocol were not registered.

### <a name="Transport.RoundTrip">func</a> (\*Transport) [RoundTrip](./transport.go#L306)
``` go
func (t *Transport) RoundTrip(req *Request) (*Response, error)
```
RoundTrip implements the RoundTripper interface.

For higher-level HTTP client support (such as handling of cookies
and redirects), see Get, Post, and the Client type.

- - -
Generated by [godoc2ghmd](https://github.com/GandalfUK/godoc2ghmd)