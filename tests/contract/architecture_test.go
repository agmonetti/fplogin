package contract_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCoreArchitectureBoundary(t *testing.T) {
	t.Parallel()
	root := filepath.Clean("../../internal/core")
	forbiddenImports := []string{"fplogin/adapters/", "fplogin/platforms/"}
	forbiddenControlValues := map[string]struct{}{
		"sddm":                      {},
		"arch":                      {},
		"org.fplogin.adapter.sddm":  {},
		"org.fplogin.platform.arch": {},
	}
	fileset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fileset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			for _, prefix := range forbiddenImports {
				if strings.HasPrefix(value, prefix) {
					t.Errorf("core imports implementation package %q in %s", value, path)
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			if _, forbidden := forbiddenControlValues[strings.ToLower(value)]; forbidden {
				t.Errorf("core contains implementation-specific control value %q in %s", value, path)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
