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
globalThis.fetch=async url=>{
 if(url===iss+'/cdn-cgi/access/certs')return {ok:true,json:async()=>({keys:[jwk]})};
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
assert.equal(await ACCESS(assertion(await jwt({nbf:now-10})),accessEnv),true,'valid nbf');
assert.equal(await ACCESS(assertion(await jwt({nbf:now+3600})),accessEnv),false,'future nbf');
assert.equal(await ACCESS(assertion(await jwt({nbf:'tomorrow'})),accessEnv),false,'malformed nbf');
assert.equal(await ACCESS(assertion(await jwt({exp:now-1})),accessEnv),false,'expired');
assert.equal(await ACCESS(assertion(await jwt({iss:'https://wrong.cloudflareaccess.com'})),accessEnv),false,'issuer mismatch');
assert.equal(await ACCESS(assertion(await jwt({aud:['other']})),accessEnv),false,'audience mismatch');
const tampered=(await jwt()).split('.');
tampered[2]=(tampered[2][0]==='A'?'B':'A')+tampered[2].slice(1);
assert.equal(await ACCESS(assertion(tampered.join('.')),accessEnv),false,'invalid signature');

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
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'ACCESS_JWT_REJECTED');
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
