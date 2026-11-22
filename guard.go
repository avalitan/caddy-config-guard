package configguard

import (
 "bytes"
 "crypto/x509"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "log"
 "net/http"
 "strings"

 "github.com/caddyserver/caddy/v2"
 "github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() { caddy.RegisterModule(Guard{}) }

// Guard inspects proposed Admin API configuration fragments before forwarding.
// Place it behind the existing Admin Gate's path and method restrictions.
type Guard struct {
 PolicyURIPrefix string             `json:"policy_uri_prefix,omitempty"`
 Profiles        map[string]Profile `json:"profiles,omitempty"`
 Default         Profile            `json:"default_policy,omitempty"`
 MaxBodyBytes    int64              `json:"max_body_bytes,omitempty"`
 ValidateIDs     bool               `json:"validate_ids,omitempty"`
 IdentityPrefix  string             `json:"identity_prefix,omitempty"`
 Separator       string             `json:"separator,omitempty"`
 AuditOnly       bool               `json:"audit_only,omitempty"`
}

type Profile struct {
 AllowHandlers []string `json:"allow_handlers,omitempty"`
 AllowMatchers []string `json:"allow_matchers,omitempty"`
 AllowCIDRs    []string `json:"allow_cidrs,omitempty"`
 AllowLoopback bool     `json:"allow_loopback,omitempty"`
}

func (Guard) CaddyModule() caddy.ModuleInfo {
 return caddy.ModuleInfo{ID:"http.handlers.config_guard", New:func() caddy.Module { return new(Guard) }}
}

func (g *Guard) Provision(_ caddy.Context) error {
 if g.PolicyURIPrefix == "" { g.PolicyURIPrefix = "urn:avalitan:caddy:guard:" }
 if g.MaxBodyBytes == 0 { g.MaxBodyBytes = 1024*1024 }
 if g.MaxBodyBytes < 0 || g.MaxBodyBytes > 16*1024*1024 { return fmt.Errorf("max_body_bytes must be 1..16777216") }
 if g.Separator == "" { g.Separator = "~" }
 if g.Separator != "~" { return fmt.Errorf("v1 supports separator ~ only") }
 if g.IdentityPrefix == "" { g.IdentityPrefix = "site_rules_" }
 for name,p:=range g.Profiles {
  if name=="" || strings.Contains(name,":") {return fmt.Errorf("invalid profile name %q",name)}
  if err:=validateProfile(p);err!=nil{return fmt.Errorf("profile %q: %w",name,err)}
 }
 return validateProfile(g.Default)
}

func (g *Guard) ServeHTTP(w http.ResponseWriter,r *http.Request,next caddyhttp.Handler) error {
 cert,err:=verifiedCertificate(r)
 if err!=nil {return respond(w,403,"unverified_client",err.Error())}
 // Admin Gate remains responsible for path and method authorization.
 if r.Method!=http.MethodPost && r.Method!=http.MethodPut && r.Method!=http.MethodPatch {
  return next.ServeHTTP(w,r)
 }
 if r.Body==nil {return respond(w,400,"missing_body","JSON request body required")}
 body,err:=io.ReadAll(io.LimitReader(r.Body,g.MaxBodyBytes+1))
 if err!=nil {return respond(w,400,"read_error",err.Error())}
 if int64(len(body))>g.MaxBodyBytes {return respond(w,413,"body_too_large","configuration body exceeds limit")}
 var doc any
 decoder:=json.NewDecoder(bytes.NewReader(body))
 decoder.UseNumber()
 if err:=decoder.Decode(&doc);err!=nil{return respond(w,400,"invalid_json",err.Error())}
 var trailing any
 if err:=decoder.Decode(&trailing);err!=io.EOF{return respond(w,400,"invalid_json","trailing JSON data")}
 opts:=validationOptions{policy:g.policy(cert),identity:cert.Subject.CommonName,prefix:g.IdentityPrefix,separator:g.Separator,checkIDs:g.ValidateIDs}
 if err:=validateDocument(doc,opts);err!=nil {
  if !g.AuditOnly {return respond(w,403,"policy_denied",err.Error())}
  log.Printf("config_guard audit rejection: %s",err)
 }
 r.Body=io.NopCloser(bytes.NewReader(body))
 r.ContentLength=int64(len(body))
 return next.ServeHTTP(w,r)
}

func verifiedCertificate(r *http.Request)(*x509.Certificate,error) {
 if r.TLS==nil || len(r.TLS.VerifiedChains)==0 || len(r.TLS.PeerCertificates)==0 {
  return nil,errors.New("mTLS client certificate has not been verified")
 }
 cert:=r.TLS.PeerCertificates[0]
 if cert.Subject.CommonName=="" {return nil,errors.New("client certificate CN is empty")}
 return cert,nil
}

func (g *Guard) policy(cert *x509.Certificate) Profile {
 p:=g.Default
 for _,u:=range cert.URIs {
  if !strings.HasPrefix(u.String(),g.PolicyURIPrefix){continue}
  name:=strings.TrimPrefix(u.String(),g.PolicyURIPrefix)
  grant,ok:=g.Profiles[name]
  if !ok {continue}
  p.AllowHandlers=append(p.AllowHandlers,grant.AllowHandlers...)
  p.AllowMatchers=append(p.AllowMatchers,grant.AllowMatchers...)
  p.AllowCIDRs=append(p.AllowCIDRs,grant.AllowCIDRs...)
  p.AllowLoopback=p.AllowLoopback||grant.AllowLoopback
 }
 return p
}

func respond(w http.ResponseWriter,status int,code,message string)error {
 w.Header().Set("Content-Type","application/json")
 w.Header().Set("Cache-Control","no-store")
 w.WriteHeader(status)
 return json.NewEncoder(w).Encode(map[string]any{"error":"config_guard_denied","reason":code,"message":message})
}

var _ caddy.Provisioner=(*Guard)(nil)
var _ caddyhttp.MiddlewareHandler=(*Guard)(nil)
