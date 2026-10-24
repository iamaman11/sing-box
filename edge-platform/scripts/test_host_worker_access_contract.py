#!/usr/bin/env python3
"""Execute the real generated Worker JS with signed Cloudflare Access JWT fixtures.

No network, secrets or cloud mutations. Node 22 is included on the CI runner.
"""
from pathlib import Path
import subprocess

source = Path("edge-platform/crates/edge-orchestrator/src/cloudflare_credential_plane_command.rs").read_text(encoding="utf-8")
start = 'let source = r#"'
end = '"#\n        .replace("__PROJECTION__"'
assert source.count(start) == source.count(end) == 1, "exactly one generated Worker source"
js = source.split(start, 1)[1].split(end, 1)[0]
for marker, value in {
    "__PROJECTION__": "2",
    "__HOST_SIGNER_PROJECTION__": "2",
    "__DUMMY_A_DIGEST__": "a" * 64,
    "__DUMMY_B_DIGEST__": "b" * 64,
    "__DUMMY_A_GENERATION__": "1",
    "__DUMMY_B_GENERATION__": "2",
}.items():
    js = js.replace(marker, value)
assert "__" not in js, "unexpanded Worker template placeholder"

fixture = r"""
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const keys = await crypto.subtle.generateKey({
 name:'RSASSA-PKCS1-v1_5', hash:'SHA-256', modulusLength:2048,
 publicExponent:new Uint8Array([1,0,1])
},true,['sign','verify']);
const jwk=await crypto.subtle.exportKey('jwk',keys.publicKey);
jwk.kid='test-access-key';
const now=Math.floor(Date.now()/1000);
const iss='https://test.cloudflareaccess.com',aud='test-audience';
const release='a'.repeat(64);
const approvedAt=new Date((now-10)*1000).toISOString();
let githubMode='approved';
let jwksMode='valid';
globalThis.fetch=async (url,init)=>{
 if(url===iss+'/cdn-cgi/access/certs'){
   assert.equal(init?.redirect,'manual','Workers supports manual redirects, not error');
   if(jwksMode==='fetch_fail')throw Error('unavailable JWKS endpoint');
   if(jwksMode==='same_zone')throw new TypeError('Cloudflare 1042 same-zone Worker fetch denied');
   if(jwksMode==='cloudflare_ip')throw new TypeError('subrequest 1024 to Cloudflare-owned IP');
   if(jwksMode==='host_denied')throw new TypeError('Error 1021 host it cannot access');
   if(jwksMode==='redirect')throw new TypeError('Redirect mode is set to error');
   if(jwksMode==='timeout')throw Object.assign(new Error('connection timed out'),{name:'TimeoutError'});
   if(jwksMode==='dns')throw new Error('DNS lookup failed');
   if(jwksMode==='tls')throw new Error('TLS certificate error');
   if(jwksMode==='invocation')throw new TypeError('Illegal invocation');
   if(jwksMode==='type_error')throw new TypeError('fetch failed');
   if(jwksMode==='http')return {ok:false,status:503};
   if(jwksMode==='http_redirect')return {ok:false,status:302,json:async()=>{throw Error('redirect followed')}};
   if(jwksMode==='invalid')return {ok:true,json:async()=>({})};
   if(jwksMode==='missing_kid')return {ok:true,json:async()=>({keys:[]})};
   if(jwksMode==='import_bad')return {ok:true,json:async()=>({keys:[{kid:jwk.kid,kty:'RSA',n:'invalid'}]})};
   return {ok:true,json:async()=>({keys:[jwk]})};
 }
 if(githubMode==='offline')throw Error('simulated GitHub outage');
 if(url.endsWith('/issues/comments/6346290327'))return {ok:true,json:async()=>({
   user:{id:githubMode==='denied'?123:44100369},
   issue_url:'https://api.github.com/repos/iamaman11/sing-box/issues/1',
   created_at:approvedAt,updated_at:approvedAt,
   body:'/host apply application-acceptance-2'
 })};
 if(url.endsWith('/releases/tags/edge-release-'+release))return {ok:true,json:async()=>({
   tag_name:'edge-release-'+release,draft:false,prerelease:false,
   target_commitish:'b'.repeat(40)
 })};
 throw Error('unexpected fixture fetch: '+url);
};
const header={alg:'RS256',kid:'test-access-key'};
function enc(v){return Buffer.from(typeof v==='string'?v:JSON.stringify(v)).toString('base64url')}
async function jwt(extra={}){
 const c={iss,aud:[aud],iat:now-10,exp:now+300,...extra};
 const data=enc(header)+'.'+enc(c);
 const sig=await crypto.subtle.sign('RSASSA-PKCS1-v1_5',keys.privateKey,TE.encode(data));
 return data+'.'+Buffer.from(sig).toString('base64url');
}
const accessEnv={EDGE_HOST_ACCESS_ISSUER:iss,EDGE_HOST_ACCESS_AUD:aud};
function assertion(t){return {headers:new Headers({'Cf-Access-Jwt-Assertion':t})}}
assert.equal(await ACCESS(assertion(await jwt()),accessEnv),true,'signed JWT without optional nbf');
assert.equal(await ACCESS(assertion(await jwt({aud})),accessEnv),true,'exact single-string JWT audience');
assert.equal(await ACCESS(assertion(await jwt({aud:[aud,'other-app']})),accessEnv),true,'exact array JWT audience');
assert.equal(await ACCESS(assertion(await jwt({aud:'other-app'})),accessEnv),false,'wrong single-string audience');
assert.equal(await ACCESS(assertion(await jwt({aud:42})),accessEnv),false,'numeric audience is invalid');
assert.equal(await ACCESS(assertion(await jwt({aud:[aud,42]})),accessEnv),false,'mixed-type array audience is invalid');
assert.equal(await ACCESS(assertion(await jwt({aud:[]})),accessEnv),false,'empty audience array is invalid');
assert.equal(await ACCESS(assertion(await jwt({nbf:now-10})),accessEnv),true,'valid nbf');
assert.equal(await ACCESS(assertion(await jwt({nbf:now+3600})),accessEnv),false,'future nbf');
assert.equal(await ACCESS(assertion(await jwt({nbf:'tomorrow'})),accessEnv),false,'malformed nbf');
assert.equal(await ACCESS(assertion(await jwt({exp:now-1})),accessEnv),false,'expired');
assert.equal(await ACCESS(assertion(await jwt({iss:'https://wrong.cloudflareaccess.com'})),accessEnv),false,'issuer mismatch');
assert.equal(await ACCESS(assertion(await jwt({aud:['other']})),accessEnv),false,'audience mismatch');
const tampered=(await jwt()).split('.');
tampered[2]=(tampered[2][0]==='A'?'B':'A')+tampered[2].slice(1);
assert.equal(await ACCESS(assertion(tampered.join('.')),accessEnv),false,'invalid signature');
// The real Worker offers one GET-only diagnostic on the EXISTING authorizer
// route: it can validate JWT but must never mint HostAuthorization.
const hostUrl=new URL('https://vm-worker.example/v1/host/authorize');
const getProof=async claims=>HOST_AUTH_DIAGNOSTIC({method:'GET',...assertion(await jwt(claims))},accessEnv,hostUrl);
let proof=await getProof();
assert.equal(proof.status,204,'valid JWT GET proof');
assert.equal(proof.headers.get('X-Host-Authorization-Scope'),'READ_ONLY_NO_MUTATION');
proof=await getProof({aud:['wrong']});
assert.equal(proof.status,403,'wrong audience GET proof must fail');
assert.equal(proof.headers.get('X-Host-Authorization-Reason'),'JWT_AUDIENCE_MISMATCH');
for(const [mode,reason] of [
 ['fetch_fail','JWT_JWKS_FETCH_FAILED'],
 ['same_zone','JWT_JWKS_FETCH_SAME_ZONE_BLOCKED'],
 ['cloudflare_ip','JWT_JWKS_FETCH_CLOUDFLARE_IP_BLOCKED'],
 ['host_denied','JWT_JWKS_FETCH_HOST_BLOCKED'],
 ['redirect','JWT_JWKS_FETCH_REDIRECT_BLOCKED'],
 ['http_redirect','JWT_JWKS_FETCH_REDIRECT_BLOCKED'],
 ['timeout','JWT_JWKS_FETCH_TIMEOUT'],
 ['dns','JWT_JWKS_FETCH_DNS_FAILED'],
 ['tls','JWT_JWKS_FETCH_TLS_FAILED'],
 ['invocation','JWT_JWKS_FETCH_ILLEGAL_INVOCATION'],
 ['type_error','JWT_JWKS_FETCH_TYPE_ERROR'],
 ['http','JWT_JWKS_HTTP_UNAVAILABLE'],
 ['invalid','JWT_JWKS_INVALID'],
 ['missing_kid','JWT_KID_NOT_FOUND'],
 ['import_bad','JWT_KEY_IMPORT_FAILED'],
]){
 jwksMode=mode;
 proof=await getProof();
 assert.equal(proof.status,403,mode+' must fail closed');
 assert.equal(proof.headers.get('X-Host-Authorization-Reason'),reason,mode+' typed reason');
}
jwksMode='valid';

const info={id:'issue1-comment-6346290327',m:'application-acceptance-2',kind:2,action:2,
 when:now,release,resource:'sing-box'};
assert.equal(await GITHUB(info,{EDGE_HOST_GITHUB_ACTOR_ID:'44100369'},now),'APPROVED');
githubMode='denied';
assert.equal(await GITHUB(info,{EDGE_HOST_GITHUB_ACTOR_ID:'44100369'},now),'DENIED');
githubMode='offline';
assert.equal(await GITHUB(info,{EDGE_HOST_GITHUB_ACTOR_ID:'44100369'},now),'UNAVAILABLE');

const ed=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
const pkcs8=await crypto.subtle.exportKey('pkcs8',ed.privateKey);
const env={...accessEnv,EDGE_HOST_GITHUB_ACTOR_ID:'44100369',
 EDGE_HOST_SIGNING_KEY_ID:'test-signer',
 EDGE_HOST_SIGNING_PKCS8_BASE64:Buffer.from(pkcs8).toString('base64url')};
const bytes=CAT(FNUM(1,1),FLD(2,TE.encode(info.m)),FNUM(3,2),
 FLD(4,TE.encode('sing-box')),FLD(5,TE.encode(info.id)),FNUM(6,2),
 FLD(7,new Uint8Array(32).fill(1)),FLD(8,new Uint8Array(32).fill(2)),
 FLD(9,new Uint8Array(32).fill(0xaa)),FNUM(11,now));
assert.ok(INFO(bytes),'canonical HostIntent fixture');
const url=new URL('https://vm-worker.example/v1/host/authorize');
const req=async t=>new Request(url,{method:'POST',
 headers:{'Cf-Access-Jwt-Assertion':t,'Content-Type':'application/x-protobuf'},body:bytes});
githubMode='approved';
let response=await AUTHORIZE(await req(await jwt()),env,url);
assert.equal(response.status,200,'approved HostIntent signed with nbf-absent JWT');
response=await AUTHORIZE(await req(await jwt({nbf:now+3600})),env,url);
assert.equal(response.status,403);
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'JWT_NOT_YET_VALID');
response=await AUTHORIZE(await req(''),env,url);
assert.equal(response.status,403);
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'JWT_MISSING');
response=await AUTHORIZE(await req(await jwt({aud:['wrong']})),env,url);
assert.equal(response.status,403);
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'JWT_AUDIENCE_MISMATCH');
response=await AUTHORIZE(await req(await jwt({iss:'https://wrong.cloudflareaccess.com'})),env,url);
assert.equal(response.status,403);
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'JWT_ISSUER_MISMATCH');
response=await AUTHORIZE(await req(await jwt({exp:now-1})),env,url);
assert.equal(response.status,403);
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'JWT_EXPIRED');
githubMode='denied';
response=await AUTHORIZE(await req(await jwt()),env,url);
assert.equal(response.status,403);
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'GITHUB_APPROVAL_DENIED');
githubMode='offline';
response=await AUTHORIZE(await req(await jwt()),env,url);
assert.equal(response.status,503);
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'GITHUB_DEPENDENCY_UNAVAILABLE');
console.log('host_worker_access_contract=PASS');
"""
result=subprocess.run(["node","--input-type=module"],input=js+"\n"+fixture,
 text=True,capture_output=True,check=False,timeout=30)
if result.returncode:
    raise SystemExit("Worker host access fixture failed:\n"+result.stdout+"\n"+result.stderr)
print(result.stdout.strip())
