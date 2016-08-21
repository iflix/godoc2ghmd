package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/godoc"
)

// $ go list std
// Packages within /internal and /vendor have been omitted from this list.
// This is up-to-date as of Go 1.7.
var goListStd = `archive/tar
archive/zip
bufio
bytes
compress/bzip2
compress/flate
compress/gzip
compress/lzw
compress/zlib
container/heap
container/list
container/ring
context
crypto
crypto/aes
crypto/cipher
crypto/des
crypto/dsa
crypto/ecdsa
crypto/elliptic
crypto/hmac
crypto/md5
crypto/rand
crypto/rc4
crypto/rsa
crypto/sha1
crypto/sha256
crypto/sha512
crypto/subtle
crypto/tls
crypto/x509
crypto/x509/pkix
database/sql
database/sql/driver
debug/dwarf
debug/elf
debug/gosym
debug/macho
debug/pe
debug/plan9obj
encoding
encoding/ascii85
encoding/asn1
encoding/base32
encoding/base64
encoding/binary
encoding/csv
encoding/gob
encoding/hex
encoding/json
encoding/pem
encoding/xml
errors
expvar
flag
fmt
go/ast
go/build
go/constant
go/doc
go/format
go/importer
go/internal/gccgoimporter
go/internal/gcimporter
go/parser
go/printer
go/scanner
go/token
go/types
hash
hash/adler32
hash/crc32
hash/crc64
hash/fnv
html
html/template
image
image/color
image/color/palette
image/draw
image/gif
image/internal/imageutil
image/jpeg
image/png
index/suffixarray
io
io/ioutil
log
log/syslog
math
math/big
math/cmplx
math/rand
mime
mime/multipart
mime/quotedprintable
net
net/http
net/http/cgi
net/http/cookiejar
net/http/fcgi
net/http/httptest
net/http/httptrace
net/http/httputil
net/http/internal
net/http/pprof
net/internal/socktest
net/mail
net/rpc
net/rpc/jsonrpc
net/smtp
net/textproto
net/url
os
os/exec
os/signal
os/user
path
path/filepath
reflect
regexp
regexp/syntax
runtime
runtime/cgo
runtime/debug
runtime/internal/atomic
runtime/internal/sys
runtime/pprof
runtime/race
runtime/trace
sort
strconv
strings
sync
sync/atomic
syscall
testing
testing/iotest
testing/quick
text/scanner
text/tabwriter
text/template
text/template/parse
time
unicode
unicode/utf16
unicode/utf8
unsafe
`

func getStdLib() map[string]bool {
	importPaths := make(map[string]bool)

	envList := os.Getenv("GO_LIST_STD")
	if envList != "" {
		for _, importPath := range strings.Split(envList, "\n") {
			if importPath != "" {
				importPaths[importPath] = true
			}
		}
		return importPaths
	}

	for _, importPath := range strings.Split(goListStd, "\n") {
		if importPath != "" {
			importPaths[importPath] = true
		}
	}
	return importPaths
}

func importAsFunc(importPath string) string {
	if *importAs != "" {
		return *importAs
	}
	return importPath
}

func listImportsFunc(info *godoc.PageInfo, imports []string, importPath string) string {
	var repoOwnerAndName string
	if strings.HasPrefix(importPath, "github.com") {
		repoOwnerAndName = strings.Join(strings.Split(importPath[len("github.com"):], "/")[:2], "")
	}

	var nonStd []string
	for _, imp := range imports {
		if !stdLib[imp] {
			nonStd = append(nonStd, imp)
		}
	}
	if len(nonStd) == 0 {
		return "No packages beyond the Go standard library are imported."
	}
	if !*importLinks || repoOwnerAndName == "" {
		return "- " + strings.Join(nonStd, "\n- ")
	}

	for i, imp := range nonStd {
		if strings.HasPrefix(imp, "github.com/"+repoOwnerAndName) {
			rel, err := filepath.Rel(importPath, imp)
			if err != nil {
				continue
			}
			nonStd[i] = fmt.Sprintf("[%s](./%s)", imp, rel)
			continue
		}
		godocUrl := "https://godoc.org/" + imp
		if !*verifyImportLinks || isValidGodocUrl(godocUrl, importLinksState) {
			nonStd[i] = fmt.Sprintf("[%s](%s)", imp, godocUrl)
		}
	}

	return "- " + strings.Join(nonStd, "\n- ")
}

func isValidGodocUrl(url string, validityMap map[string]string) bool {
	if validityMap != nil && validityMap[url] != "" {
		return validityMap[url] == validImportKey
	}

	resp, err := http.Head(url)
	resp.Body.Close()

	var validity string
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		validity = validImportKey
	} else {
		validity = invalidImportKey
	}

	validityMap[url] = validity
	if *importLinksFile != "" {
		f, err := os.OpenFile(*importLinksFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return validity == validImportKey
		}
		defer f.Close()
		_, err = f.WriteString(fmt.Sprintf("%s %s\n", url, validity))
		if err != nil {
			panic(err)
		}
	}

	return validity == validImportKey
}
