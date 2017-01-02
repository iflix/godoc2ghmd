use 'godoc cmd/io/ioutil' for documentation on the io/ioutil command 

# ioutil
`import "io/ioutil"`

* [Overview](#pkg-overview)
* [Imported Packages](#pkg-imports)
* [Index](#pkg-index)
* [Examples](#pkg-examples)

## <a name="pkg-overview">Overview</a>
Package ioutil implements some I/O utility functions.

## <a name="pkg-imports">Imported Packages</a>

No packages beyond the Go standard library are imported.

## <a name="pkg-index">Index</a>
* [Variables](#pkg-variables)
* [func NopCloser(r io.Reader) io.ReadCloser](#NopCloser)
* [func ReadAll(r io.Reader) ([]byte, error)](#ReadAll)
* [func ReadDir(dirname string) ([]os.FileInfo, error)](#ReadDir)
* [func ReadFile(filename string) ([]byte, error)](#ReadFile)
* [func TempDir(dir, prefix string) (name string, err error)](#TempDir)
* [func TempFile(dir, prefix string) (f \*os.File, err error)](#TempFile)
* [func WriteFile(filename string, data []byte, perm os.FileMode) error](#WriteFile)

#### <a name="pkg-examples">Examples</a>
* [ReadAll](#example_ReadAll)
* [ReadDir](#example_ReadDir)
* [TempDir](#example_TempDir)
* [TempFile](#example_TempFile)

#### <a name="pkg-files">Package files</a>
[ioutil.go](./ioutil.go) [tempfile.go](./tempfile.go) 

## <a name="pkg-variables">Variables</a>
``` go
var Discard io.Writer = devNull(0)
```
Discard is an io.Writer on which all Write calls succeed
without doing anything.

## <a name="NopCloser">func</a> [NopCloser](./ioutil.go#L122)
``` go
func NopCloser(r io.Reader) io.ReadCloser
```
NopCloser returns a ReadCloser with a no-op Close method wrapping
the provided Reader r.

## <a name="ReadAll">func</a> [ReadAll](./ioutil.go#L41)
``` go
func ReadAll(r io.Reader) ([]byte, error)
```
ReadAll reads from r until an error or EOF and returns the data it read.
A successful call returns err == nil, not err == EOF. Because ReadAll is
defined to read from src until EOF, it does not treat an EOF from Read
as an error to be reported.

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
r := strings.NewReader("Go is a general-purpose language designed with systems programming in mind.")
	
	b, err := ioutil.ReadAll(r)
	if err != nil {
	    log.Fatal(err)
	}
	
	fmt.Printf("%s", b)
	
	// Output:
	// Go is a general-purpose language designed with systems programming in mind.
```

</details>

## <a name="ReadDir">func</a> [ReadDir](./ioutil.go#L100)
``` go
func ReadDir(dirname string) ([]os.FileInfo, error)
```
ReadDir reads the directory named by dirname and returns
a list of directory entries sorted by filename.

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
files, err := ioutil.ReadDir(".")
	if err != nil {
	    log.Fatal(err)
	}
	
	for _, file := range files {
	    fmt.Println(file.Name())
	}
```

</details>

## <a name="ReadFile">func</a> [ReadFile](./ioutil.go#L49)
``` go
func ReadFile(filename string) ([]byte, error)
```
ReadFile reads the file named by filename and returns the contents.
A successful call returns err == nil, not err == EOF. Because ReadFile
reads the whole file, it does not treat an EOF from Read as an error
to be reported.

## <a name="TempDir">func</a> [TempDir](./tempfile.go#L76)
``` go
func TempDir(dir, prefix string) (name string, err error)
```
TempDir creates a new temporary directory in the directory dir
with a name beginning with prefix and returns the path of the
new directory. If dir is the empty string, TempDir uses the
default directory for temporary files (see os.TempDir).
Multiple programs calling TempDir simultaneously
will not choose the same directory. It is the caller's responsibility
to remove the directory when no longer needed.

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
content := []byte("temporary file's content")
	dir, err := ioutil.TempDir("", "example")
	if err != nil {
	    log.Fatal(err)
	}
	
	defer os.RemoveAll(dir) // clean up
	
	tmpfn := filepath.Join(dir, "tmpfile")
	if err := ioutil.WriteFile(tmpfn, content, 0666); err != nil {
	    log.Fatal(err)
	}
```

</details>

## <a name="TempFile">func</a> [TempFile](./tempfile.go#L47)
``` go
func TempFile(dir, prefix string) (f *os.File, err error)
```
TempFile creates a new temporary file in the directory dir
with a name beginning with prefix, opens the file for reading
and writing, and returns the resulting *os.File.
If dir is the empty string, TempFile uses the default directory
for temporary files (see os.TempDir).
Multiple programs calling TempFile simultaneously
will not choose the same file. The caller can use f.Name()
to find the pathname of the file. It is the caller's responsibility
to remove the file when no longer needed.

#### Example:

<details>
<summary>Click to expand code.</summary>

```go
content := []byte("temporary file's content")
	tmpfile, err := ioutil.TempFile("", "example")
	if err != nil {
	    log.Fatal(err)
	}
	
	defer os.Remove(tmpfile.Name()) // clean up
	
	if _, err := tmpfile.Write(content); err != nil {
	    log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
	    log.Fatal(err)
	}
```

</details>

## <a name="WriteFile">func</a> [WriteFile](./ioutil.go#L76)
``` go
func WriteFile(filename string, data []byte, perm os.FileMode) error
```
WriteFile writes data to a file named by filename.
If the file does not exist, WriteFile creates it with permissions perm;
otherwise WriteFile truncates it before writing.

- - -
Generated by [godoc2ghmd](https://github.com/GandalfUK/godoc2ghmd)