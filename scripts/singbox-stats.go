// Query cumulative counters. Batch sampling uses one helper process per tick.
package main

import (
 "context"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"
 "sync"
 "time"

 api "github.com/sagernet/sing-box/experimental/v2rayapi"
 "google.golang.org/grpc"
 "google.golang.org/grpc/credentials/insecure"
)

func query(address string) (*api.QueryStatsResponse, error) {
 conn,err:=grpc.NewClient(address,grpc.WithTransportCredentials(insecure.NewCredentials()))
 if err!=nil{return nil,err}
 defer conn.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
 result:=new(api.QueryStatsResponse)
 err=conn.Invoke(ctx,"/v2ray.core.app.stats.command.StatsService/QueryStats",&api.QueryStatsRequest{Pattern:"user>>>",Reset_:false},result)
 return result,err
}

func main() {
 address:=flag.String("server","127.0.0.1:10085","local statistics listener")
 batch:=flag.Bool("batch",false,"read node-to-address map from stdin")
 flag.Parse()
 if !*batch {
  result,err:=query(*address)
  if err!=nil{fmt.Fprintln(os.Stderr,"statistics query failed");os.Exit(1)}
  if json.NewEncoder(os.Stdout).Encode(result)!=nil{os.Exit(1)}
  return
 }
 targets:=map[string]string{}
 if json.NewDecoder(io.LimitReader(os.Stdin,65536)).Decode(&targets)!=nil||len(targets)>128{os.Exit(1)}
 results:=map[string]interface{}{}
 var mutex sync.Mutex
 var group sync.WaitGroup
 for id,endpoint:=range targets {
  group.Add(1)
  go func(id,endpoint string){
   defer group.Done()
   result,err:=query(endpoint)
   mutex.Lock();defer mutex.Unlock()
   if err!=nil{results[id]=map[string]string{"error":"statistics unavailable"}}else{results[id]=result}
  }(id,endpoint)
 }
 group.Wait()
 if json.NewEncoder(os.Stdout).Encode(results)!=nil{os.Exit(1)}
}
