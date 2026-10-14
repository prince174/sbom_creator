// External development helper. Parse source only; never execute project tools.
package main

import (
 "encoding/json"
 "fmt"
 "go/build"
 "go/parser"
 "go/token"
 "io/fs"
 "os"
 "path/filepath"
 "runtime"
 "sort"
 "strings"
)

func main() {
 if len(os.Args) != 4 { panic("usage: helper source GOOS GOARCH") }
 root, err := filepath.Abs(os.Args[1]); if err != nil { panic(err) }
 ctx := build.Default; ctx.GOOS=os.Args[2]; ctx.GOARCH=os.Args[3]; ctx.CgoEnabled=false
 dirs:=map[string]bool{}; count:=0; total:=int64(0)
 err=filepath.WalkDir(root,func(path string,d fs.DirEntry,walkErr error) error {
  if walkErr!=nil { return walkErr }
  if d.Type()&os.ModeSymlink!=0 { return fmt.Errorf("symlink unsupported: %s",path) }
  if d.IsDir() {
   if path!=root && (d.Name()=="vendor" || d.Name()==".git" || strings.HasPrefix(d.Name(),".")) { return filepath.SkipDir }
   if path!=root { if _,e:=os.Stat(filepath.Join(path,"go.mod")); e==nil { return filepath.SkipDir } }
   return nil
  }
  if !strings.HasSuffix(path,".go") || strings.HasSuffix(path,"_test.go") { return nil }
  count++; info,e:=d.Info(); if e!=nil { return e }; total+=info.Size()
  if count>10000 || info.Size()>1024*1024 || total>16*1024*1024 { return fmt.Errorf("source budget exceeded") }
  matched,e:=ctx.MatchFile(filepath.Dir(path),filepath.Base(path));if e!=nil{return e};if !matched{return nil}
  ast,e:=parser.ParseFile(token.NewFileSet(),path,nil,parser.ImportsOnly);if e!=nil{return e}
  for _,imp:=range ast.Imports { if imp.Path.Value==`"C"` { return nil } }
  if ast.Name.Name=="main" { rel,e:=filepath.Rel(root,filepath.Dir(path));if e!=nil{return e};dirs[filepath.ToSlash(rel)]=true }
  return nil
 });if err!=nil { panic(err) }
 mains:=[]string{};for dir:=range dirs {mains=append(mains,dir)};sort.Strings(mains)
 if err=json.NewEncoder(os.Stdout).Encode(map[string]any{"main_directories":mains,"parser_version":runtime.Version(),"GOOS":ctx.GOOS,"GOARCH":ctx.GOARCH,"CGO_ENABLED":false,"files_checked":count});err!=nil{panic(err)}
}
