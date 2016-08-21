// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// godoc2md converts godoc formatted package documentation into Markdown format.
//
//
// Usage
//
//    godoc2gh $PACKAGE > $GOPATH/src/$PACKAGE/README.md
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/doc"
	"go/token"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"

	"golang.org/x/tools/godoc"
	"golang.org/x/tools/godoc/vfs"
)

var (
	verbose = flag.Bool("v", false, "verbose mode")

	// file system roots
	// TODO(gri) consider the invariant that goroot always end in '/'
	goroot = flag.String("goroot", runtime.GOROOT(), "Go root directory")

	// layout control
	tabWidth       = flag.Int("tabwidth", 4, "tab width")
	showTimestamps = flag.Bool("timestamps", false, "show timestamps with directory listings")
	templateDir    = flag.String("templates", "", "directory containing alternate template files")
	showPlayground = flag.Bool("play", false, "enable playground in web interface")
	showExamples   = flag.Bool("ex", false, "show examples in command line mode")
	declLinks      = flag.Bool("links", true, "link identifiers to their declarations")
	importAs       = flag.String("import_as", "", "import path to display")
)

func usage() {
	fmt.Fprintf(os.Stderr,
		"usage: godoc2gh package [name ...]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

var (
	pres *godoc.Presentation
	fs   = vfs.NameSpace{}

	funcs = map[string]interface{}{
		"comment_md": comment_mdFunc,
		"base":       path.Base,
		"md":         mdFunc,
		"pre":        preFunc,
		"gh_url":     ghUrlFunc,
		"import_as":  importAsFunc,
	}
)

const punchCardWidth = 80

func importAsFunc(importPath string) string {
	if importAs != nil && *importAs != "" {
		return *importAs
	}
	return importPath
}

func comment_mdFunc(comment string) string {
	var buf bytes.Buffer
	ToMD(&buf, comment, nil)
	return buf.String()
}

func mdFunc(text string) string {
	text = strings.Replace(text, "*", "\\*", -1)
	text = strings.Replace(text, "_", "\\_", -1)
	return text
}

func preFunc(text string) string {
	return "``` go\n" + text + "\n```"
}

func ghUrlFunc(info *godoc.PageInfo, n interface{}) string {
	var pos, end token.Pos

	switch an := n.(type) {
	case ast.Node:
		pos = an.Pos()
		end = an.End()
	case *doc.Note:
		pos = an.Pos
		end = an.End
	default:
		panic(fmt.Sprintf("wrong type for gh_url template formatter: %T", an))
	}

	var posLine int
	var filePath string
	var linesFragment string
	if pos.IsValid() {
		p := info.FSet.Position(pos)
		posLine = p.Line
		filePath = p.Filename
		if strings.HasPrefix(filePath, "/target/") {
			filePath = filePath[len("/target/"):]
		}
		linesFragment = "#L" + strconv.Itoa(posLine)
	}
	if end.IsValid() {
		endPos := info.FSet.Position(end)
		if endPos.Line > posLine {
			linesFragment += "-L" + strconv.Itoa(endPos.Line)
		}
	}

	return "./" + filePath + linesFragment
}

func readTemplate(name, data string) *template.Template {
	// be explicit with errors (for app engine use)
	t, err := template.New(name).Funcs(pres.FuncMap()).Funcs(funcs).Parse(string(data))
	if err != nil {
		log.Fatal("readTemplate: ", err)
	}
	return t
}

func readTemplates(p *godoc.Presentation, html bool) {
	p.PackageText = readTemplate("package.txt", pkgTemplate)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	// Check usage
	if flag.NArg() == 0 {
		usage()
	}

	// use file system of underlying OS
	fs.Bind("/", vfs.OS(*goroot), "/", vfs.BindReplace)

	// Bind $GOPATH trees into Go root.
	for _, p := range filepath.SplitList(build.Default.GOPATH) {
		fs.Bind("/src/pkg", vfs.OS(p), "/src", vfs.BindAfter)
	}

	corpus := godoc.NewCorpus(fs)
	corpus.Verbose = *verbose

	pres = godoc.NewPresentation(corpus)
	pres.TabWidth = *tabWidth
	pres.ShowTimestamps = *showTimestamps
	pres.ShowPlayground = *showPlayground
	pres.ShowExamples = *showExamples
	pres.DeclLinks = *declLinks
	pres.SrcMode = false
	pres.HTMLMode = false

	readTemplates(pres, false)

	if err := godoc.CommandLine(os.Stdout, fs, pres, flag.Args()); err != nil {
		log.Print(err)
	}
}
