# build
`import "go/build"`

* [Overview](#pkg-overview)
* [Imported Packages](#pkg-imports)
* [Index](#pkg-index)

## <a name="pkg-overview">Overview</a>
Package build gathers information about Go packages.

### Go Path
The Go path is a list of directory trees containing Go source code.
It is consulted to resolve imports that cannot be found in the standard
Go tree. The default path is the value of the GOPATH environment
variable, interpreted as a path list appropriate to the operating system
(on Unix, the variable is a colon-separated string;
on Windows, a semicolon-separated string;
on Plan 9, a list).

Each directory listed in the Go path must have a prescribed structure:

The src/ directory holds source code. The path below 'src' determines
the import path or executable name.

The pkg/ directory holds installed package objects.
As in the Go tree, each target operating system and
architecture pair has its own subdirectory of pkg
(pkg/GOOS_GOARCH).

If DIR is a directory listed in the Go path, a package with
source in DIR/src/foo/bar can be imported as "foo/bar" and
has its compiled form installed to "DIR/pkg/GOOS_GOARCH/foo/bar.a"
(or, for gccgo, "DIR/pkg/gccgo/foo/libbar.a").

The bin/ directory holds compiled commands.
Each command is named for its source directory, but only
using the final element, not the entire path. That is, the
command with source in DIR/src/foo/quux is installed into
DIR/bin/quux, not DIR/bin/foo/quux. The foo/ is stripped
so that you can add DIR/bin to your PATH to get at the
installed commands.

Here's an example directory layout:

	GOPATH=/home/user/gocode
	
	/home/user/gocode/
	    src/
	        foo/
	            bar/               (go code in package bar)
	                x.go
	            quux/              (go code in package main)
	                y.go
	    bin/
	        quux                   (installed command)
	    pkg/
	        linux_amd64/
	            foo/
	                bar.a          (installed package object)

### Build Constraints
A build constraint, also known as a build tag, is a line comment that begins

	// +build

that lists the conditions under which a file should be included in the package.
Constraints may appear in any kind of source file (not just Go), but
they must appear near the top of the file, preceded
only by blank lines and other line comments. These rules mean that in Go
files a build constraint must appear before the package clause.

To distinguish build constraints from package documentation, a series of
build constraints must be followed by a blank line.

A build constraint is evaluated as the OR of space-separated options.
Each option evaluates as the AND of its comma-separated terms.
Each term consists of letters, digits, underscores, and dots.
A term may be negated with a preceding !.
For example, the build constraint:

	// +build linux,386 darwin,!cgo

corresponds to the boolean formula:

	(linux AND 386) OR (darwin AND (NOT cgo))

A file may have multiple build constraints. The overall constraint is the AND
of the individual constraints. That is, the build constraints:

	// +build linux darwin
	// +build 386

corresponds to the boolean formula:

	(linux OR darwin) AND 386

During a particular build, the following words are satisfied:

	- the target operating system, as spelled by runtime.GOOS
	- the target architecture, as spelled by runtime.GOARCH
	- the compiler being used, either "gc" or "gccgo"
	- "cgo", if ctxt.CgoEnabled is true
	- "go1.1", from Go version 1.1 onward
	- "go1.2", from Go version 1.2 onward
	- "go1.3", from Go version 1.3 onward
	- "go1.4", from Go version 1.4 onward
	- "go1.5", from Go version 1.5 onward
	- "go1.6", from Go version 1.6 onward
	- "go1.7", from Go version 1.7 onward
	- "go1.8", from Go version 1.8 onward
	- "go1.9", from Go version 1.9 onward
	- "go1.10", from Go version 1.10 onward
	- "go1.11", from Go version 1.11 onward
	- "go1.12", from Go version 1.12 onward
	- "go1.13", from Go version 1.13 onward
	- any additional words listed in ctxt.BuildTags

There are no build tags for beta or minor releases.

If a file's name, after stripping the extension and a possible _test suffix,
matches any of the following patterns:

	*_GOOS
	*_GOARCH
	*_GOOS_GOARCH

(example: source_windows_amd64.go) where GOOS and GOARCH represent
any known operating system and architecture values respectively, then
the file is considered to have an implicit build constraint requiring
those terms (in addition to any explicit constraints in the file).

To keep a file from being considered for the build:

	// +build ignore

(any other unsatisfied word will work as well, but ``ignore'' is conventional.)

To build a file only when using cgo, and only on Linux and OS X:

	// +build linux,cgo darwin,cgo

Such a file is usually paired with another file implementing the
default functionality for other systems, which in this case would
carry the constraint:

	// +build !linux,!darwin !cgo

Naming a file dns_windows.go will cause it to be included only when
building the package for Windows; similarly, math_386.s will be included
only when building the package for 32-bit x86.

Using GOOS=android matches build tags and files as for GOOS=linux
in addition to android tags and files.

Using GOOS=illumos matches build tags and files as for GOOS=solaris
in addition to illumos tags and files.

### Binary-Only Packages
In Go 1.12 and earlier, it was possible to distribute packages in binary
form without including the source code used for compiling the package.
The package was distributed with a source file not excluded by build
constraints and containing a "//go:binary-only-package" comment. Like a
build constraint, this comment appeared at the top of a file, preceded
only by blank lines and other line comments and with a blank line
following the comment, to separate it from the package documentation.
Unlike build constraints, this comment is only recognized in non-test
Go source files.

The minimal source code for a binary-only package was therefore:

	//go:binary-only-package
	
	package mypkg

The source code could include additional Go code. That code was never
compiled but would be processed by tools like godoc and might be useful
as end-user documentation.

"go build" and other commands no longer support binary-only-packages.
Import and ImportDir will still set the BinaryOnly flag in packages
containing these comments for use in tools and error messages.

## <a name="pkg-imports">Imported Packages</a>

- internal/goroot
- internal/goversion

## <a name="pkg-index">Index</a>
* [Variables](#pkg-variables)
* [func ArchChar(goarch string) (string, error)](#ArchChar)
* [func IsLocalImport(path string) bool](#IsLocalImport)
* [type Context](#Context)
  * [func (ctxt \*Context) Import(path string, srcDir string, mode ImportMode) (\*Package, error)](#Context.Import)
  * [func (ctxt \*Context) ImportDir(dir string, mode ImportMode) (\*Package, error)](#Context.ImportDir)
  * [func (ctxt \*Context) MatchFile(dir, name string) (match bool, err error)](#Context.MatchFile)
  * [func (ctxt \*Context) SrcDirs() []string](#Context.SrcDirs)
* [type ImportMode](#ImportMode)
* [type MultiplePackageError](#MultiplePackageError)
  * [func (e \*MultiplePackageError) Error() string](#MultiplePackageError.Error)
* [type NoGoError](#NoGoError)
  * [func (e \*NoGoError) Error() string](#NoGoError.Error)
* [type Package](#Package)
  * [func Import(path, srcDir string, mode ImportMode) (\*Package, error)](#Import)
  * [func ImportDir(dir string, mode ImportMode) (\*Package, error)](#ImportDir)
  * [func (p \*Package) IsCommand() bool](#Package.IsCommand)

#### <a name="pkg-files">Package files</a>
[build.go](./build.go) [doc.go](./doc.go) [gc.go](./gc.go) [read.go](./read.go) [syslist.go](./syslist.go) [zcgo.go](./zcgo.go) 

## <a name="pkg-variables">Variables</a>
``` go
var ToolDir = getToolDir()
```
ToolDir is the directory containing build tools.

## <a name="ArchChar">func</a> [ArchChar](./build.go#L1774)
``` go
func ArchChar(goarch string) (string, error)
```
ArchChar returns "?" and an error.
In earlier versions of Go, the returned string was used to derive
the compiler and linker tool names, the default object file suffix,
and the default linker output name. As of Go 1.5, those strings
no longer vary by architecture; they are compile, link, .o, and a.out, respectively.

## <a name="IsLocalImport">func</a> [IsLocalImport](./build.go#L1764)
``` go
func IsLocalImport(path string) bool
```
IsLocalImport reports whether the import path is
a local import path, like ".", "..", "./foo", or "../foo".

## <a name="Context">type</a> [Context](./build.go#L33-L101)
``` go
type Context struct {
    GOARCH      string // target architecture
    GOOS        string // target operating system
    GOROOT      string // Go root
    GOPATH      string // Go path
    CgoEnabled  bool   // whether cgo files are included
    UseAllFiles bool   // use files regardless of +build lines, file names
    Compiler    string // compiler to assume when computing target paths

    // The build and release tags specify build constraints
    // that should be considered satisfied when processing +build lines.
    // Clients creating a new context may customize BuildTags, which
    // defaults to empty, but it is usually an error to customize ReleaseTags,
    // which defaults to the list of Go releases the current release is compatible with.
    // BuildTags is not set for the Default build Context.
    // In addition to the BuildTags and ReleaseTags, build constraints
    // consider the values of GOARCH and GOOS as satisfied tags.
    // The last element in ReleaseTags is assumed to be the current release.
    BuildTags   []string
    ReleaseTags []string

    // The install suffix specifies a suffix to use in the name of the installation
    // directory. By default it is empty, but custom builds that need to keep
    // their outputs separate can set InstallSuffix to do so. For example, when
    // using the race detector, the go command uses InstallSuffix = "race", so
    // that on a Linux/386 system, packages are written to a directory named
    // "linux_386_race" instead of the usual "linux_386".
    InstallSuffix string

    // JoinPath joins the sequence of path fragments into a single path.
    // If JoinPath is nil, Import uses filepath.Join.
    JoinPath func(elem ...string) string

    // SplitPathList splits the path list into a slice of individual paths.
    // If SplitPathList is nil, Import uses filepath.SplitList.
    SplitPathList func(list string) []string

    // IsAbsPath reports whether path is an absolute path.
    // If IsAbsPath is nil, Import uses filepath.IsAbs.
    IsAbsPath func(path string) bool

    // IsDir reports whether the path names a directory.
    // If IsDir is nil, Import calls os.Stat and uses the result's IsDir method.
    IsDir func(path string) bool

    // HasSubdir reports whether dir is lexically a subdirectory of
    // root, perhaps multiple levels below. It does not try to check
    // whether dir exists.
    // If so, HasSubdir sets rel to a slash-separated path that
    // can be joined to root to produce a path equivalent to dir.
    // If HasSubdir is nil, Import uses an implementation built on
    // filepath.EvalSymlinks.
    HasSubdir func(root, dir string) (rel string, ok bool)

    // ReadDir returns a slice of os.FileInfo, sorted by Name,
    // describing the content of the named directory.
    // If ReadDir is nil, Import uses ioutil.ReadDir.
    ReadDir func(dir string) ([]os.FileInfo, error)

    // OpenFile opens a file (not a directory) for reading.
    // If OpenFile is nil, Import uses os.Open.
    OpenFile func(path string) (io.ReadCloser, error)
}

```
A Context specifies the supporting context for a build.

``` go
var Default Context = defaultContext()
```
Default is the default Context for builds.
It uses the GOARCH, GOOS, GOROOT, and GOPATH environment variables
if set, or else the compiled code's GOARCH, GOOS, and GOROOT.

### <a name="Context.Import">func</a> (\*Context) [Import](./build.go#L500)
``` go
func (ctxt *Context) Import(path string, srcDir string, mode ImportMode) (*Package, error)
```
Import returns details about the Go package named by the import path,
interpreting local import paths relative to the srcDir directory.
If the path is a local import path naming a package that can be imported
using a standard import path, the returned package will set p.ImportPath
to that path.

In the directory containing the package, .go, .c, .h, and .s files are
considered part of the package except for:

	- .go files in package documentation
	- files starting with _ or . (likely editor temporary files)
	- files with build constraints not satisfied by the context

If an error occurs, Import returns a non-nil error and a non-nil
*Package containing partial information.

### <a name="Context.ImportDir">func</a> (\*Context) [ImportDir](./build.go#L448)
``` go
func (ctxt *Context) ImportDir(dir string, mode ImportMode) (*Package, error)
```
ImportDir is like Import but processes the Go package found in
the named directory.

### <a name="Context.MatchFile">func</a> (\*Context) [MatchFile](./build.go#L1231)
``` go
func (ctxt *Context) MatchFile(dir, name string) (match bool, err error)
```
MatchFile reports whether the file with the given name in the given directory
matches the context and would be included in a Package created by ImportDir
of that directory.

MatchFile considers the name of the file and may use ctxt.OpenFile to
read some or all of the file's content.

### <a name="Context.SrcDirs">func</a> (\*Context) [SrcDirs](./build.go#L244)
``` go
func (ctxt *Context) SrcDirs() []string
```
SrcDirs returns a list of package source root directories.
It draws from the current Go root and Go path but omits directories
that do not exist.

## <a name="ImportMode">type</a> [ImportMode](./build.go#L339)
``` go
type ImportMode uint
```
An ImportMode controls the behavior of the Import method.

``` go
const (
    // If FindOnly is set, Import stops after locating the directory
    // that should contain the sources for a package. It does not
    // read any files in the directory.
    FindOnly ImportMode = 1 << iota

    // If AllowBinary is set, Import can be satisfied by a compiled
    // package object without corresponding sources.
    //
    // Deprecated:
    // The supported way to create a compiled-only package is to
    // write source code containing a //go:binary-only-package comment at
    // the top of the file. Such a package will be recognized
    // regardless of this flag setting (because it has source code)
    // and will have BinaryOnly set to true in the returned Package.
    AllowBinary

    // If ImportComment is set, parse import comments on package statements.
    // Import returns an error if it finds a comment it cannot understand
    // or finds conflicting comments in multiple source files.
    // See golang.org/s/go14customimport for more information.
    ImportComment

    // By default, Import searches vendor directories
    // that apply in the given source directory before searching
    // the GOROOT and GOPATH roots.
    // If an Import finds and returns a package using a vendor
    // directory, the resulting ImportPath is the complete path
    // to the package, including the path elements leading up
    // to and including "vendor".
    // For example, if Import("y", "x/subdir", 0) finds
    // "x/vendor/y", the returned package's ImportPath is "x/vendor/y",
    // not plain "y".
    // See golang.org/s/go15vendor for more information.
    //
    // Setting IgnoreVendor ignores vendor directories.
    //
    // In contrast to the package's ImportPath,
    // the returned package's Imports, TestImports, and XTestImports
    // are always the exact import paths from the source files:
    // Import makes no attempt to resolve or check those paths.
    IgnoreVendor
)
```

## <a name="MultiplePackageError">type</a> [MultiplePackageError](./build.go#L465-L469)
``` go
type MultiplePackageError struct {
    Dir      string   // directory containing files
    Packages []string // package names found
    Files    []string // corresponding files: Files[i] declares package Packages[i]
}

```
MultiplePackageError describes a directory containing
multiple buildable Go source files for multiple packages.

### <a name="MultiplePackageError.Error">func</a> (\*MultiplePackageError) [Error](./build.go#L471)
``` go
func (e *MultiplePackageError) Error() string
```

## <a name="NoGoError">type</a> [NoGoError](./build.go#L455-L457)
``` go
type NoGoError struct {
    Dir string
}

```
NoGoError is the error used by Import to describe a directory
containing no buildable Go source files. (It may still contain
test files, files hidden by build tags, and so on.)

### <a name="NoGoError.Error">func</a> (\*NoGoError) [Error](./build.go#L459)
``` go
func (e *NoGoError) Error() string
```

## <a name="Package">type</a> [Package](./build.go#L386-L437)
``` go
type Package struct {
    Dir           string   // directory containing package sources
    Name          string   // package name
    ImportComment string   // path in import comment on package statement
    Doc           string   // documentation synopsis
    ImportPath    string   // import path of package ("" if unknown)
    Root          string   // root of Go tree where this package lives
    SrcRoot       string   // package source root directory ("" if unknown)
    PkgRoot       string   // package install root directory ("" if unknown)
    PkgTargetRoot string   // architecture dependent install root directory ("" if unknown)
    BinDir        string   // command install directory ("" if unknown)
    Goroot        bool     // package found in Go root
    PkgObj        string   // installed .a file
    AllTags       []string // tags that can influence file selection in this directory
    ConflictDir   string   // this directory shadows Dir in $GOPATH
    BinaryOnly    bool     // cannot be rebuilt from source (has //go:binary-only-package comment)

    // Source files
    GoFiles        []string // .go source files (excluding CgoFiles, TestGoFiles, XTestGoFiles)
    CgoFiles       []string // .go source files that import "C"
    IgnoredGoFiles []string // .go source files ignored for this build
    InvalidGoFiles []string // .go source files with detected problems (parse error, wrong package name, and so on)
    CFiles         []string // .c source files
    CXXFiles       []string // .cc, .cpp and .cxx source files
    MFiles         []string // .m (Objective-C) source files
    HFiles         []string // .h, .hh, .hpp and .hxx source files
    FFiles         []string // .f, .F, .for and .f90 Fortran source files
    SFiles         []string // .s source files
    SwigFiles      []string // .swig files
    SwigCXXFiles   []string // .swigcxx files
    SysoFiles      []string // .syso system object files to add to archive

    // Cgo directives
    CgoCFLAGS    []string // Cgo CFLAGS directives
    CgoCPPFLAGS  []string // Cgo CPPFLAGS directives
    CgoCXXFLAGS  []string // Cgo CXXFLAGS directives
    CgoFFLAGS    []string // Cgo FFLAGS directives
    CgoLDFLAGS   []string // Cgo LDFLAGS directives
    CgoPkgConfig []string // Cgo pkg-config directives

    // Dependency information
    Imports   []string                    // import paths from GoFiles, CgoFiles
    ImportPos map[string][]token.Position // line information for Imports

    // Test information
    TestGoFiles    []string                    // _test.go files in package
    TestImports    []string                    // import paths from TestGoFiles
    TestImportPos  map[string][]token.Position // line information for TestImports
    XTestGoFiles   []string                    // _test.go files outside package
    XTestImports   []string                    // import paths from XTestGoFiles
    XTestImportPos map[string][]token.Position // line information for XTestImports
}

```
A Package describes the Go package found in a directory.

### <a name="Import">func</a> [Import](./build.go#L1316)
``` go
func Import(path, srcDir string, mode ImportMode) (*Package, error)
```
Import is shorthand for Default.Import.

### <a name="ImportDir">func</a> [ImportDir](./build.go#L1321)
``` go
func ImportDir(dir string, mode ImportMode) (*Package, error)
```
ImportDir is shorthand for Default.ImportDir.

### <a name="Package.IsCommand">func</a> (\*Package) [IsCommand](./build.go#L442)
``` go
func (p *Package) IsCommand() bool
```
IsCommand reports whether the package is considered a
command to be installed (not just a library).
Packages named "main" are treated as commands.

- - -
Generated by [godoc2ghmd](https://github.com/iflix/godoc2ghmd)