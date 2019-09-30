# doc
`import "go/doc"`

* [Overview](#pkg-overview)
* [Imported Packages](#pkg-imports)
* [Index](#pkg-index)

## <a name="pkg-overview">Overview</a>
Package doc extracts source code documentation from a Go AST.

## <a name="pkg-imports">Imported Packages</a>

- internal/lazyregexp

## <a name="pkg-index">Index</a>
* [Variables](#pkg-variables)
* [func IsPredeclared(s string) bool](#IsPredeclared)
* [func Synopsis(s string) string](#Synopsis)
* [func ToHTML(w io.Writer, text string, words map[string]string)](#ToHTML)
* [func ToText(w io.Writer, text string, indent, preIndent string, width int)](#ToText)
* [type Example](#Example)
  * [func Examples(files ...\*ast.File) []\*Example](#Examples)
* [type Filter](#Filter)
* [type Func](#Func)
* [type Mode](#Mode)
* [type Note](#Note)
* [type Package](#Package)
  * [func New(pkg \*ast.Package, importPath string, mode Mode) \*Package](#New)
  * [func (p \*Package) Filter(f Filter)](#Package.Filter)
* [type Type](#Type)
* [type Value](#Value)

#### <a name="pkg-files">Package files</a>
[comment.go](./comment.go) [doc.go](./doc.go) [example.go](./example.go) [exports.go](./exports.go) [filter.go](./filter.go) [reader.go](./reader.go) [synopsis.go](./synopsis.go) 

## <a name="pkg-variables">Variables</a>
``` go
var IllegalPrefixes = []string{
    "copyright",
    "all rights",
    "author",
}
```

## <a name="IsPredeclared">func</a> [IsPredeclared](./reader.go#L867)
``` go
func IsPredeclared(s string) bool
```
IsPredeclared reports whether s is a predeclared identifier.

## <a name="Synopsis">func</a> [Synopsis](./synopsis.go#L68)
``` go
func Synopsis(s string) string
```
Synopsis returns a cleaned version of the first sentence in s.
That sentence ends after the first period followed by space and
not preceded by exactly one uppercase letter. The result string
has no \n, \r, or \t characters and uses only single spaces between
words. If s starts with any of the IllegalPrefixes, the result
is the empty string.

## <a name="ToHTML">func</a> [ToHTML](./comment.go#L306)
``` go
func ToHTML(w io.Writer, text string, words map[string]string)
```
ToHTML converts comment text to formatted HTML.
The comment was prepared by DocReader,
so it is known not to have leading, trailing blank lines
nor to have trailing spaces at the end of lines.
The comment markers have already been removed.

Each span of unindented non-blank lines is converted into
a single paragraph. There is one exception to the rule: a span that
consists of a single line, is followed by another paragraph span,
begins with a capital letter, and contains no punctuation
other than parentheses and commas is formatted as a heading.

A span of indented lines is converted into a <pre> block,
with the common indent prefix removed.

URLs in the comment text are converted into links; if the URL also appears
in the words map, the link is taken from the map (if the corresponding map
value is the empty string, the URL is not converted into a link).

Go identifiers that appear in the words map are italicized; if the corresponding
map value is not the empty string, it is considered a URL and the word is converted
into a link.

## <a name="ToText">func</a> [ToText](./comment.go#L420)
``` go
func ToText(w io.Writer, text string, indent, preIndent string, width int)
```
ToText prepares comment text for presentation in textual output.
It wraps paragraphs of text to width or fewer Unicode code points
and then prefixes each line with the indent. In preformatted sections
(such as program text), it prefixes each non-blank line with preIndent.

## <a name="Example">type</a> [Example](./example.go#L22-L32)
``` go
type Example struct {
    Name        string // name of the item being exemplified
    Doc         string // example function doc string
    Code        ast.Node
    Play        *ast.File // a whole program version of the example
    Comments    []*ast.CommentGroup
    Output      string // expected output
    Unordered   bool
    EmptyOutput bool // expect empty output
    Order       int  // original source code order
}

```
An Example represents an example function found in a source files.

### <a name="Examples">func</a> [Examples](./example.go#L47)
``` go
func Examples(files ...*ast.File) []*Example
```
Examples returns the examples found in the files, sorted by Name field.
The Order fields record the order in which the examples were encountered.

Playable Examples must be in a package whose name ends in "_test".
An Example is "playable" (the Play field is non-nil) in either of these
circumstances:

	- The example function is self-contained: the function references only
	  identifiers from other packages (or predeclared identifiers, such as
	  "int") and the test file does not include a dot import.
	- The entire test file is the example: the file contains exactly one
	  example function, zero test or benchmark functions, and at least one
	  top-level function, type, variable, or constant declaration other
	  than the example function.

## <a name="Filter">type</a> [Filter](./filter.go#L9)
``` go
type Filter func(string) bool
```

## <a name="Func">type</a> [Func](./doc.go#L56-L66)
``` go
type Func struct {
    Doc  string
    Name string
    Decl *ast.FuncDecl

    // methods
    // (for functions, these fields have the respective zero value)
    Recv  string // actual   receiver "T" or "*T"
    Orig  string // original receiver "T" or "*T"
    Level int    // embedding level; 0 means not embedded
}

```
Func is the documentation for a func declaration.

## <a name="Mode">type</a> [Mode](./doc.go#L79)
``` go
type Mode int
```
Mode values control the operation of New.

``` go
const (
    // AllDecls says to extract documentation for all package-level
    // declarations, not just exported ones.
    AllDecls Mode = 1 << iota

    // AllMethods says to show all embedded methods, not just the ones of
    // invisible (unexported) anonymous fields.
    AllMethods

    // PreserveAST says to leave the AST unmodified. Originally, pieces of
    // the AST such as function bodies were nil-ed out to save memory in
    // godoc, but not all programs want that behavior.
    PreserveAST
)
```

## <a name="Note">type</a> [Note](./doc.go#L72-L76)
``` go
type Note struct {
    Pos, End token.Pos // position range of the comment containing the marker
    UID      string    // uid found with the marker
    Body     string    // note body text
}

```
A Note represents a marked comment starting with "MARKER(uid): note body".
Any note with a marker of 2 or more upper case [A-Z] letters and a uid of
at least one character is recognized. The ":" following the uid is optional.
Notes are collected in the Package.Notes map indexed by the notes marker.

## <a name="Package">type</a> [Package](./doc.go#L14-L31)
``` go
type Package struct {
    Doc        string
    Name       string
    ImportPath string
    Imports    []string
    Filenames  []string
    Notes      map[string][]*Note

    // Deprecated: For backward compatibility Bugs is still populated,
    // but all new code should use Notes instead.
    Bugs []string

    // declarations
    Consts []*Value
    Types  []*Type
    Vars   []*Value
    Funcs  []*Func
}

```
Package is the documentation for an entire package.

### <a name="New">func</a> [New](./doc.go#L99)
``` go
func New(pkg *ast.Package, importPath string, mode Mode) *Package
```
New computes the package documentation for the given package AST.
New takes ownership of the AST pkg and may edit or overwrite it.

### <a name="Package.Filter">func</a> (\*Package) [Filter](./filter.go#L99)
``` go
func (p *Package) Filter(f Filter)
```
Filter eliminates documentation for names that don't pass through the filter f.
TODO(gri): Recognize "Type.Method" as a name.

## <a name="Type">type</a> [Type](./doc.go#L43-L53)
``` go
type Type struct {
    Doc  string
    Name string
    Decl *ast.GenDecl

    // associated declarations
    Consts  []*Value // sorted list of constants of (mostly) this type
    Vars    []*Value // sorted list of variables of (mostly) this type
    Funcs   []*Func  // sorted list of functions returning this type
    Methods []*Func  // sorted list of methods (including embedded ones) of this type
}

```
Type is the documentation for a type declaration.

## <a name="Value">type</a> [Value](./doc.go#L34-L40)
``` go
type Value struct {
    Doc   string
    Names []string // var or const names in declaration order
    Decl  *ast.GenDecl
    // contains filtered or unexported fields
}

```
Value is the documentation for a (possibly grouped) var or const declaration.

- - -
Generated by [godoc2ghmd](https://github.com/GandalfUK/godoc2ghmd)