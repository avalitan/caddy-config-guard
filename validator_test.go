package configguard

import (
 "crypto/x509"
 "encoding/json"
 "net/url"
 "testing"
)
func opts() validationOptions {return validationOptions{
 policy:Profile{AllowHandlers:[]string{"reverse_proxy","subroute","static_response"},AllowMatchers:[]string{"path"},AllowCIDRs:[]string{"192.168.2.0/24"}},
 identity:"philine.avalitan.moe",prefix:"site_rules_",separator:"~",checkIDs:true,
}}
func TestAuthorizedProxy(t *testing.T){
 data:=[]byte(`{"@id":"site_rules_philine.avalitan.moe~vikunja","handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"192.168.2.228:3456"}]}]}`)
 var doc any;if err:=json.Unmarshal(data,&doc);err!=nil{t.Fatal(err)}
 if err:=validateDocument(doc,opts());err!=nil{t.Fatal(err)}
}
func TestDenyDangerous(t *testing.T){
 tests:=[]string{
  `{"handle":[{"handler":"file_server","root":"/"}]}`,
  `{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:2021"}]}]}`,
  `{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"unix//var/run/caddy.sock"}]}]}`,
  `{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"192.168.2.228:3456"}],"transport":{"protocol":"http","tls":{}}}]}`,
  `{"@id":"site_rules_other.example~vikunja","handle":[{"handler":"static_response","body":"bad"}]}`,
  `{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"file_server"}]}]}]}`,
  `{"handle":[{"handler":"subroute","routes":[{"@id":"site_rules_other.example~x","handle":[{"handler":"static_response","body":"bad"}]}]}]}`,
 }
 for _,s:=range tests{
  var doc any;if err:=json.Unmarshal([]byte(s),&doc);err!=nil{t.Fatal(err)}
  if err:=validateDocument(doc,opts());err==nil{t.Errorf("accepted unsafe document: %s",s)}
 }
}
func TestURISANPolicies(t *testing.T){
 u,_:=url.Parse("urn:avalitan:caddy:guard:advanced")
 g:=Guard{PolicyURIPrefix:"urn:avalitan:caddy:guard:",Default:Profile{AllowHandlers:[]string{"reverse_proxy"}},Profiles:map[string]Profile{
 "advanced":{AllowHandlers:[]string{"subroute"}},
 }}
 p:=g.policy(&x509.Certificate{URIs:[]*url.URL{u}})
 if len(p.AllowHandlers)!=2{t.Fatalf("got %v",p.AllowHandlers)}
}
func TestRejectUnknownProfileModule(t *testing.T){
 if err:=validateProfile(Profile{AllowHandlers:[]string{"exec"}});err==nil{t.Fatal("unexpected permission")}
}
