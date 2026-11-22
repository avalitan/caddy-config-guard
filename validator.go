package configguard

import (
 "encoding/json"
 "fmt"
 "net"
 "net/netip"
 "strconv"
 "strings"
)

// This validator intentionally understands a small set of Caddy JSON shapes.
// Unknown keys and unsupported module configurations fail closed. Merely
// listing a module in a certificate profile never authorizes arbitrary fields.
type validationOptions struct {
 policy Profile
 identity string
 prefix string
 separator string
 checkIDs bool
}
func validateProfile(p Profile) error {
 for _,m:=range p.AllowHandlers {
  if _,ok:=knownHandlers[m];!ok{return fmt.Errorf("unsupported handler %q",m)}
 }
 for _,m:=range p.AllowMatchers {
  if _,ok:=knownMatchers[m];!ok{return fmt.Errorf("unsupported matcher %q",m)}
 }
 for _,c:=range p.AllowCIDRs {
  if _,err:=netip.ParsePrefix(c);err!=nil{return fmt.Errorf("invalid CIDR %q: %w",c,err)}
 }
 return nil
}
var knownHandlers = map[string]bool{
 "reverse_proxy":true,"static_response":true,"headers":true,
 "rewrite":true,"subroute":true,
}
var knownMatchers = map[string]bool{
 "host":true,"path":true,"method":true,"header":true,
}
func (o validationOptions) handlerAllowed(name string) bool {
 for _,s:=range o.policy.AllowHandlers {if name==s{return true}}
 return false
}
func (o validationOptions) matcherAllowed(name string) bool {
 for _,s:=range o.policy.AllowMatchers {if name==s{return true}}
 return false
}
func object(v any,where string)(map[string]any,error){
 m,ok:=v.(map[string]any);if !ok{return nil,fmt.Errorf("%s: expected object",where)};return m,nil
}
func array(v any,where string)([]any,error){
 a,ok:=v.([]any);if !ok{return nil,fmt.Errorf("%s: expected array",where)};return a,nil
}
func stringValue(v any,where string)(string,error){
 s,ok:=v.(string);if !ok{return "",fmt.Errorf("%s: expected string",where)};return s,nil
}
func fields(m map[string]any,where string,allowed ...string)error{
 set:=map[string]bool{};for _,k:=range allowed{set[k]=true}
 for k:=range m{if !set[k]{return fmt.Errorf("%s/%s: unsupported field",where,k)}}
 return nil
}
func stringsArray(v any,where string)error{
 a,e:=array(v,where);if e!=nil{return e}
 for i,x:=range a{if _,e=stringValue(x,fmt.Sprintf("%s/%d",where,i));e!=nil{return e}}
 return nil
}
func (o validationOptions) checkID(m map[string]any,where string)error{
 if v,ok:=m["@id"];ok{
  s,e:=stringValue(v,where+"/@id");if e!=nil{return e}
  if o.checkIDs && !strings.HasPrefix(s,o.prefix+o.identity+o.separator){
   return fmt.Errorf("%s/@id: id %q is outside the client's namespace",where,s)
  }
 }
 return nil
}
func validateDocument(v any,o validationOptions)error{
 switch x:=v.(type){
 case map[string]any:
  return o.route(x,"$")
 case []any:
  for i,e:=range x {m,err:=object(e,fmt.Sprintf("$/%d",i));if err!=nil{return err};if err=o.route(m,fmt.Sprintf("$/%d",i));err!=nil{return err}}
  return nil
 default:return fmt.Errorf("$: expected route object or route array")
 }
}
func(o validationOptions)route(m map[string]any,where string)error{
 if err:=fields(m,where,"@id","match","handle","terminal");err!=nil{return err}
 if err:=o.checkID(m,where);err!=nil{return err}
 if x,ok:=m["terminal"];ok{if _,ok:=x.(bool);!ok{return fmt.Errorf("%s/terminal: expected boolean",where)}}
 if x,ok:=m["match"];ok{
  a,e:=array(x,where+"/match");if e!=nil{return e}
  for i,v:=range a{
   mm,e:=object(v,fmt.Sprintf("%s/match/%d",where,i));if e!=nil{return e}
   for name,val:=range mm{
    if !o.matcherAllowed(name){return fmt.Errorf("%s/match/%d/%s: matcher not permitted",where,i,name)}
    if err:=o.matcher(name,val,where+"/match/"+strconv.Itoa(i)+"/"+name);err!=nil{return err}
   }
  }
 }
 x,ok:=m["handle"];if !ok{return fmt.Errorf("%s: handle required",where)}
 a,e:=array(x,where+"/handle");if e!=nil{return e}
 if len(a)==0{return fmt.Errorf("%s/handle: empty handlers not supported",where)}
 for i,v:=range a{
  hh,e:=object(v,fmt.Sprintf("%s/handle/%d",where,i));if e!=nil{return e}
  if e=o.handler(hh,fmt.Sprintf("%s/handle/%d",where,i));e!=nil{return e}
 }
 return nil
}
func(o validationOptions)matcher(name string,v any,where string)error{
 if name=="header"{
  m,e:=object(v,where);if e!=nil{return e}
  for key,value:=range m{
   if key==""{return fmt.Errorf("%s: empty header name",where)}
   if e=stringsArray(value,where+"/"+key);e!=nil{return e}
  }
  return nil
 }
 return stringsArray(v,where)
}
func (o validationOptions)handler(m map[string]any,where string)error{
 name,e:=stringValue(m["handler"],where+"/handler");if e!=nil{return e}
 if !o.handlerAllowed(name){return fmt.Errorf("%s/handler: module %q not permitted",where,name)}
 if e=o.checkID(m,where);e!=nil{return e}
 switch name {
 case "reverse_proxy":
  if e=fields(m,where,"handler","@id","upstreams");e!=nil{return e}
  up,ok:=m["upstreams"];if !ok{return fmt.Errorf("%s: upstreams required",where)}
  a,e:=array(up,where+"/upstreams");if e!=nil{return e}
  if len(a)==0{return fmt.Errorf("%s: no upstreams",where)}
  for i,v:=range a{
   at:=fmt.Sprintf("%s/upstreams/%d",where,i)
   x,e:=object(v,at);if e!=nil{return e}
   if e=fields(x,at,"dial");e!=nil{return e}
   dial,e:=stringValue(x["dial"],at+"/dial");if e!=nil{return e}
   if e=o.dial(dial,at+"/dial");e!=nil{return e}
  }
 case "static_response":
  if e=fields(m,where,"handler","@id","status_code","body","headers");e!=nil{return e}
  if v,ok:=m["status_code"];ok{
   switch v.(type){case json.Number,float64,string:default:return fmt.Errorf("%s/status_code: invalid type",where)}
  }
  if v,ok:=m["body"];ok{if _,e=stringValue(v,where+"/body");e!=nil{return e}}
  if v,ok:=m["headers"];ok{if e=headerValues(v,where+"/headers");e!=nil{return e}}
 case "headers":
  if e=fields(m,where,"handler","@id","request","response");e!=nil{return e}
  for _,direction:=range []string{"request","response"}{
   if v,ok:=m[direction];ok{
    mm,e:=object(v,where+"/"+direction);if e!=nil{return e}
    if e=fields(mm,where+"/"+direction,"set","add","delete");e!=nil{return e}
    for _,kind:=range []string{"set","add"} {
     if val,ok:=mm[kind];ok{if e=headerValues(val,where+"/"+direction+"/"+kind);e!=nil{return e}}
    }
    if val,ok:=mm["delete"];ok{if e=stringsArray(val,where+"/"+direction+"/delete");e!=nil{return e}}
   }
  }
 case "rewrite":
  if e=fields(m,where,"handler","@id","method","uri","strip_path_prefix","strip_path_suffix");e!=nil{return e}
  for _,key:=range []string{"method","uri","strip_path_prefix","strip_path_suffix"}{
   if v,ok:=m[key];ok{if _,e=stringValue(v,where+"/"+key);e!=nil{return e}}
  }
 case "subroute":
  if e=fields(m,where,"handler","@id","routes");e!=nil{return e}
  a,e:=array(m["routes"],where+"/routes");if e!=nil{return e}
  for i,v:=range a{
   at:=fmt.Sprintf("%s/routes/%d",where,i)
   rr,e:=object(v,at);if e!=nil{return e}
   if e=o.route(rr,at);e!=nil{return e}
  }
 default:return fmt.Errorf("%s/handler: unsupported module",where)
 }
 return nil
}
func headerValues(v any,where string)error{
 m,e:=object(v,where);if e!=nil{return e}
 for key,val:=range m{
  if key==""{return fmt.Errorf("%s: empty header name",where)}
  if e=stringsArray(val,where+"/"+key);e!=nil{return e}
 }
 return nil
}
func(o validationOptions)dial(dial,where string)error{
 host,port,e:=net.SplitHostPort(dial)
 if e!=nil{return fmt.Errorf("%s: literal IP:port required: %w",where,e)}
 ip,e:=netip.ParseAddr(host);if e!=nil{return fmt.Errorf("%s: only literal IPs are permitted",where)}
 ip=ip.Unmap()
 n,e:=strconv.Atoi(port);if e!=nil||n<1||n>65535{return fmt.Errorf("%s: invalid port",where)}
 if ip.IsLoopback()&&!o.policy.AllowLoopback{return fmt.Errorf("%s: loopback is not permitted",where)}
 for _,raw:=range o.policy.AllowCIDRs{
  prefix,e:=netip.ParsePrefix(raw);if e!=nil{return e}
  if prefix.Contains(ip){return nil}
 }
 return fmt.Errorf("%s: IP %s is not in an allowed CIDR",where,ip)
}
