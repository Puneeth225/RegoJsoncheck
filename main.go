package main

import (
	"context"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"

	//"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/rego"
)

func isRegoFile(name string) bool {
	return strings.HasSuffix(name, bundle.RegoExt) && !strings.HasSuffix(name, "_test"+bundle.RegoExt)
}

func sanitisePath(path string) string {
	vol := filepath.VolumeName(path)
	path = strings.TrimPrefix(path, vol)

	return strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(path), "./"), "/")
}

type Scanner struct {
}

func (s *Scanner) loadPoliciesFromDirs(target fs.FS, paths []string) (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module)
	for _, path := range paths {
		if err := fs.WalkDir(target, sanitisePath(path), func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !isRegoFile(info.Name()) {
				return nil
			}
			data, err := fs.ReadFile(target, filepath.ToSlash(path))
			if err != nil {
				return err
			}
			module, err := ast.ParseModuleWithOpts(path, string(data), ast.ParserOptions{
				ProcessAnnotation: true,
			})
			if err != nil {
				return err
			}
			modules[path] = module
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return modules, nil
}

func main() {
	var arr []string
	p := "/Users/puneeth.sharma_averl/hello/Go/regogo"

	fl := os.DirFS(p)
	arr = append(arr, "eg1.rego")
	fmt.Printf("rego folder is at -- %s\n", p)
	var s Scanner
	mp, err := s.loadPoliciesFromDirs(fl, arr)
	if err != nil {
		fmt.Printf("%s", err)
	} else {
		fmt.Println(mp["eg1.rego"])
	}

	b, err := ioutil.ReadFile("C:/Users/puneeth.sharma_averl/hello/Go/regogoquery/policy.rego")
	if err != nil {
		fmt.Println(err)
		return
	}

	// parse the contents of the file into an ast.Module

	in, err1 := ioutil.ReadFile("C:/Users/puneeth.sharma_averl/hello/Go/regogoquery/input.json")
	if err1 != nil {
		fmt.Println(err1)
		return
	}
	input := string(in)
	r := rego.New(
		rego.Query("data.example.allow"),
		rego.Module("policy.rego", string(b)),
		rego.Input(input),
	)

	rs, err := r.Eval(context.Background())

	if err != nil {
		fmt.Println("Error evaluating Rego file:", err)
		return
	}
	// Print the result
	fmt.Println(rs)
	if rs != nil {
		fmt.Println("Access granted")
	} else {
		fmt.Println("Denied")
	}
}
