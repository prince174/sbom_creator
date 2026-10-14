// External benchmark helper: read binary metadata without executing the binary.
package main

import (
 "debug/buildinfo"
 "encoding/json"
 "os"
)

func main() {
 if len(os.Args)!=2 { panic("usage: helper binary") }
 stat,err:=os.Stat(os.Args[1]);if err!=nil{panic(err)}
 if !stat.Mode().IsRegular() || stat.Size()>64*1024*1024 { panic("unsupported binary size/type") }
 info,err:=buildinfo.ReadFile(os.Args[1]);if err!=nil{panic(err)}
 if err=json.NewEncoder(os.Stdout).Encode(info);err!=nil{panic(err)}
}
