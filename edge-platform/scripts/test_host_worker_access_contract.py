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
# Evaluate the EXACT production Worker router, not an isolated helper. The
# local fixture has no network or Cloudflare credentials.
route = "export default{async fetch(q,e){"
assert js.count(route) == 1, "exactly one active Worker dispatch"
js = js.replace(route, "const ACTIVE_VM_WORKER={async fetch(q,e){", 1)

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
let approvedAt=new Date((now-10)*1000).toISOString();
let githubMode='approved';
let adminComment=null;
let appMode='valid';
let jwksMode='valid';
// October 2026 ghs_APPID_JWT is ~520 chars and contains dots.
// Keep stateless and legacy token internals opaque.
const legacyToken='ghs_TESTTOKEN1234567890';
const statelessToken='ghs_5456373_'+
 ['a'.repeat(160),'b'.repeat(160),'c'.repeat(160)].join('.');
const appPkcs8=await crypto.subtle.exportKey('pkcs8',keys.privateKey);
const appEnv={EDGE_HOST_GITHUB_ACTOR_ID:'44100369',
 EDGE_HOST_GITHUB_APP_PKCS8_BASE64:Buffer.from(appPkcs8).toString('base64url')};
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
 const issueToken='https://api.github.com/app/installations/174880562/access_tokens';
 if(url===issueToken){
  assert.equal(init?.method,'POST','installation token is minted, never replayed');
  assert.equal(init?.redirect,'manual');
  assert.deepEqual(JSON.parse(init.body),{repositories:['sing-box'],
   permissions:{contents:'read',issues:'read',pull_requests:'read'}});
  const auth=init.headers.Authorization;
  assert.ok(auth.startsWith('Bearer '));
  const segments=auth.slice(7).split('.');
  assert.equal(segments.length,3);
  assert.deepEqual(JSON.parse(Buffer.from(segments[0],'base64url').toString()),{alg:'RS256',typ:'JWT'});
  const claims=JSON.parse(Buffer.from(segments[1],'base64url').toString());
  assert.equal(claims.iss,'5456373');
  assert.equal(claims.exp-claims.iat,600);
  assert.equal(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',keys.publicKey,
   Buffer.from(segments[2],'base64url'),TE.encode(segments[0]+'.'+segments[1])),true);
  if(appMode==='fetch')throw new TypeError('secret transport');
  if(appMode==='redirect')return{ok:false,status:302};
  if(appMode==='http')return{ok:false,status:403,headers:new Headers({'X-RateLimit-Remaining':'0'})};
  if(appMode==='decode')return{ok:true,status:201,json:async()=>{throw new SyntaxError('private token bytes')}};
  return{ok:true,status:201,json:async()=>({
   token:appMode==='legacy'?legacyToken:
    appMode==='token_controls'?'ghs_BAD TOKEN':statelessToken,
   expires_at:new Date((now+1800)*1000).toISOString(),
   permissions:{metadata:'read',issues:'read',contents:'read',pull_requests:'read'},
   repository_selection:'selected',
   repositories:[{id:1221750822,full_name:appMode==='scope'?'iamaman11/other':'iamaman11/sing-box'}]
  })};
 }
 const api='https://api.github.com/repos/iamaman11/sing-box';
 assert.ok(url.startsWith(api+'/'),'all approval reads stay on the pinned GitHub origin');
 assert.equal(init?.redirect,'manual','Cloudflare Workers does not support redirect:error');
 assert.equal(init?.headers?.Authorization,
  'Bearer '+(appMode==='legacy'?legacyToken:statelessToken),
  'repository reads require installation token, not operator PAT or anonymous');
 if(githubMode==='offline')throw Error('simulated GitHub outage');
 const failureAt={http_comment:'/issues/comments/6346290327',
  http_release:'/releases/tags/edge-release-'+release,
  http_main:'/git/ref/heads/main',
  http_pulls:'/commits/'+'b'.repeat(40)+'/pulls?per_page=20',
  decode_comment:'/issues/comments/6346290327',
  decode_release:'/releases/tags/edge-release-'+release,
  decode_main:'/git/ref/heads/main',
  decode_pulls:'/commits/'+'b'.repeat(40)+'/pulls?per_page=20'}[githubMode];
 if(failureAt&&url===api+failureAt){
  if(githubMode.startsWith('http_'))return{ok:false,status:429,
   headers:new Headers({'X-RateLimit-Remaining':'0','X-RateLimit-Reset':'1780000000',
    'Retry-After':'60','X-GitHub-Request-Id':'ABC-123'})};
  return{ok:true,status:200,json:async()=>{throw new SyntaxError('private response bytes')}};
 }
 const redirectAt={redirect_comment:'/issues/comments/6346290327',
  redirect_release:'/releases/tags/edge-release-'+release,
  redirect_main:'/git/ref/heads/main',
  redirect_pulls:'/commits/'+'b'.repeat(40)+'/pulls?per_page=20'}[githubMode];
 if(redirectAt&&url===api+redirectAt)return {ok:false,status:302,
  json:async()=>{throw Error('forbidden redirected response was consumed')}};
 if(url.endsWith('/issues/comments/6346290327'))return {ok:true,json:async()=>({
   user:{id:githubMode==='denied'?123:44100369},
   issue_url:'https://api.github.com/repos/iamaman11/sing-box/issues/1',
   created_at:approvedAt,updated_at:approvedAt,
   body:adminComment||'/host apply application-acceptance-2'
 })};
 if(url.endsWith('/releases/tags/edge-release-'+release))return {ok:true,json:async()=>({
   tag_name:'edge-release-'+release,draft:false,prerelease:false,
   target_commitish:'b'.repeat(40)
 })};
 if(url.endsWith('/git/ref/heads/main'))return {ok:true,
  json:async()=>({object:{type:'commit',sha:'b'.repeat(40)}})};
 if(url.endsWith('/commits/'+'b'.repeat(40)+'/pulls?per_page=20'))return {ok:true,
  json:async()=>[{merged_at:new Date((now-120)*1000).toISOString(),draft:false,
   base:{ref:'main'},head:{repo:{full_name:'iamaman11/sing-box'},
     ref:'host-receipt-application-acceptance-2-6346290327'},
   merge_commit_sha:'b'.repeat(40),
   title:'host: register native receipt for application-acceptance-2'}]};
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
assert.equal(await GITHUB(info,appEnv,now),'APPROVED',
 'stateless 2026 token with JWT dots must pass');
appMode='legacy';
assert.equal(await GITHUB(info,appEnv,now),'APPROVED',
 'legacy opaque token remains valid');
appMode='valid';
// Missing Worker binding, invalid private key, unsafe token scope or
// inaccessible issuance must never fall back to GitHub anonymous reads.
let authFailure=await GITHUB(info,{EDGE_HOST_GITHUB_ACTOR_ID:'44100369'},now);
assert.equal(authFailure.stage,'GITHUB_APP_JWT');
assert.equal(authFailure.kind,'CONFIG_MISSING');
authFailure=await GITHUB(info,{...appEnv,EDGE_HOST_GITHUB_APP_PKCS8_BASE64:'invalid'},now);
assert.equal(authFailure.stage,'GITHUB_APP_JWT');
assert.equal(authFailure.kind,'SIGN_EXCEPTION');
for(const [mode,stage,kind] of [
 ['http','GITHUB_INSTALLATION_TOKEN','HTTP'],
 ['redirect','GITHUB_INSTALLATION_TOKEN','REDIRECT'],
 ['fetch','GITHUB_INSTALLATION_TOKEN','FETCH_EXCEPTION'],
 ['decode','GITHUB_INSTALLATION_TOKEN','RESPONSE_DECODE'],
 ['scope','GITHUB_INSTALLATION_TOKEN','RESPONSE_INVALID'],
 ['token_controls','GITHUB_INSTALLATION_TOKEN','RESPONSE_INVALID']
]){
 appMode=mode;
 authFailure=await GITHUB(info,appEnv,now);
 assert.equal(authFailure.decision,'UNAVAILABLE',mode);
 assert.equal(authFailure.stage,stage,mode);
 assert.equal(authFailure.kind,kind,mode);
 assert.equal(JSON.stringify(authFailure).includes('secret transport'),false);
 assert.equal(JSON.stringify(authFailure).includes('private token bytes'),false);
}
appMode='valid';
githubMode='denied';
assert.equal(await GITHUB(info,appEnv,now),'DENIED');
githubMode='offline';
let failure=await GITHUB(info,appEnv,now);
assert.equal(failure.decision,'UNAVAILABLE');
assert.equal(failure.stage,'GITHUB_COMMENT');
assert.equal(failure.kind,'FETCH_EXCEPTION');
assert.equal(failure.exception_class,'Error');
// Cover all four exact GitHub reads, including old first-use receipt approval.
// A 302 must stop at its original URL and never be followed.
approvedAt=new Date((now-302)*1000).toISOString();
const oldInfo={...info,when:now-280};
githubMode='approved';
assert.equal(await GITHUB(oldInfo,appEnv,now),'APPROVED');
for(const mode of ['redirect_comment','redirect_release','redirect_main','redirect_pulls']){
 githubMode=mode;
 failure=await GITHUB(oldInfo,appEnv,now);
 assert.equal(failure.decision,'UNAVAILABLE',mode+' must fail closed');
 assert.equal(failure.kind,'REDIRECT',mode+' must block all 3xx');
 assert.equal(failure.http_status,302,mode+' does not follow Location');
}
// Each distinct GitHub subrequest must surface its stage and safe failure kind.
for(const [mode,stage] of [
 ['http_comment','GITHUB_COMMENT'],['http_release','GITHUB_RELEASE'],
 ['http_main','GITHUB_MAIN'],['http_pulls','GITHUB_PULLS'],
 ['decode_comment','GITHUB_COMMENT'],['decode_release','GITHUB_RELEASE'],
 ['decode_main','GITHUB_MAIN'],['decode_pulls','GITHUB_PULLS']
]){
 githubMode=mode;
 failure=await GITHUB(oldInfo,appEnv,now);
 assert.equal(failure.decision,'UNAVAILABLE',mode);
 assert.equal(failure.stage,stage,mode);
 if(mode.startsWith('http_')){
  assert.equal(failure.kind,'HTTP',mode);
  assert.equal(failure.http_status,429,mode);
  assert.equal(failure.rate_limit_remaining,'0',mode);
  assert.equal(failure.retry_after,'60',mode);
  assert.equal(failure.github_request_id,'ABC-123',mode);
 }else{
  assert.equal(failure.kind,'RESPONSE_DECODE',mode);
  assert.equal(failure.exception_class,'SyntaxError',mode);
  assert.equal(JSON.stringify(failure).includes('private response bytes'),false,mode+' redacts');
 }
}
approvedAt=new Date((now-10)*1000).toISOString();

const ed=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
const pkcs8=await crypto.subtle.exportKey('pkcs8',ed.privateKey);
const env={...accessEnv,...appEnv,
 EDGE_HOST_SIGNING_KEY_ID:'test-signer',
 EDGE_HOST_SIGNING_PKCS8_BASE64:Buffer.from(pkcs8).toString('base64url')};
// End-to-end signed identity proof goes through the EXACT production Worker
// fetch router, Access/JWKS verifier and the live signer secret binding.
// It never reaches GitHub approval or creates a HostAuthorization.
function proofFields(raw){
 let p=0,out=new Map();
 while(p<raw.length){
  const k=V(raw,p);assert.ok(k,"identity proof truncated key");p=k[1];
  const id=Number(k[0]>>3n),wire=Number(k[0]&7n);
  assert.ok(id>=1&&id<=6&&!out.has(id),"identity proof unknown/duplicate field");
  if(wire===0){const n=V(raw,p);assert.ok(n,"identity proof invalid integer");p=n[1];out.set(id,n[0]);}
  else if(wire===2){
   const n=V(raw,p);assert.ok(n,"identity proof invalid length");p=n[1];
   const length=Number(n[0]);assert.ok(length<=raw.length-p,"identity proof exceeds length");
   out.set(id,raw.slice(p,p+length));p+=length;
  }else throw Error("identity proof non-protobuf wire type");
 }
 assert.deepEqual([...out.keys()],[1,2,3,4,5,6],"identity proof canonical fields");
 return out;
}
const challenge=new Uint8Array(32).fill(0x5c);
const identityUrl='https://vm-worker.example/v1/host/identity?challenge='+
 Array.from(challenge,x=>x.toString(16).padStart(2,'0')).join('');
async function identityCall(url=identityUrl,settings=env,claims={}){
 return ACTIVE_VM_WORKER.fetch(new Request(url,{method:'GET',
  headers:{'Cf-Access-Jwt-Assertion':await jwt(claims)}}),settings);
}
githubMode='offline';appMode='offline';
let identityResponse=await identityCall();
assert.equal(identityResponse.status,200,"active Worker must sign live identity with no GitHub requests");
assert.equal(identityResponse.headers.get('X-Host-Authorization-Scope'),
 'SIGNED_IDENTITY_NO_MUTATION',"signed GET cannot grant host authority");
assert.equal(identityResponse.headers.get('Cache-Control'),'no-store');
const identityBody=new Uint8Array(await identityResponse.arrayBuffer());
assert.ok(identityBody.length<512,"bounded signed Worker identity");
const signedIdentity=proofFields(identityBody);
assert.equal(signedIdentity.get(1),1n);
assert.deepEqual(signedIdentity.get(2),challenge,"fresh challenge must bind exact bytes");
const publicKey=new Uint8Array(await crypto.subtle.exportKey('raw',ed.publicKey));
assert.deepEqual(signedIdentity.get(3),publicKey,"the live secret must derive this public key");
const idBytes=signedIdentity.get(4);
assert.equal(TD.decode(idBytes),'test-signer');
const signedPayload=CAT(TE.encode('sing-box/host-signer-identity/v1:'),
 challenge,publicKey,U32(idBytes.length),idBytes,U64(signedIdentity.get(5)));
assert.equal(await crypto.subtle.verify('Ed25519',ed.publicKey,signedIdentity.get(6),signedPayload),
 true,"signed challenge must verify against live public key");
const wrongChallenge=CAT(TE.encode('sing-box/host-signer-identity/v1:'),
 new Uint8Array(32).fill(0x5d),publicKey,U32(idBytes.length),idBytes,U64(signedIdentity.get(5)));
assert.equal(await crypto.subtle.verify('Ed25519',ed.publicKey,signedIdentity.get(6),wrongChallenge),
 false,"a different nonce must not accept replayed signedIdentity");
assert.equal((await identityCall('https://vm-worker.example/v1/host/identity')).status,404,
 "missing nonce must be rejected");
assert.equal((await identityCall('https://vm-worker.example/v1/host/identity?challenge=xyz')).status,404,
 "non-canonical nonce must be rejected");
assert.equal((await identityCall(identityUrl+'&another=1')).status,404,
 "multiple query params must fail closed");
assert.equal((await identityCall(identityUrl,env,{aud:['foreign-app']})).status,403,
 "foreign Cloudflare Access audience must be rejected");
assert.equal((await identityCall(identityUrl,{...env,EDGE_HOST_SIGNING_PKCS8_BASE64:'invalid'})).status,503,
 "malformed live secret must fail closed");
const missingAccess=await ACTIVE_VM_WORKER.fetch(new Request(identityUrl),env);
assert.equal(missingAccess.status,403,"signed identity requires Cloudflare Access");
assert.equal(missingAccess.headers.get('X-Host-Authorization-Reason'),'JWT_MISSING');
githubMode='approved';appMode='valid';
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
// The SAME published Worker authorizes Windows START/STOP, but ONLY if its
// authenticated GitHub issue #1 comment matches the exact typed intent.
// VM may not borrow these effects and SET_MODE/TUN remains closed.
const winBytes=(kind,action,mode=null)=>CAT(
 FNUM(1,1),FLD(2,TE.encode('sing-box-windows-lab')),FNUM(3,kind),
 FLD(4,TE.encode('sing-box')),FLD(5,TE.encode(info.id)),FNUM(6,action),
 FLD(7,new Uint8Array(32).fill(1)),FLD(8,new Uint8Array(32).fill(2)),
 FLD(9,new Uint8Array(32).fill(0xaa)),
 ...(mode===null?[]:[FNUM(10,mode)]),FNUM(11,now));
const signedWindows=async data=>AUTHORIZE(
 new Request(url,{method:'POST',headers:{
  'Cf-Access-Jwt-Assertion':await jwt(),
  'Content-Type':'application/x-protobuf'},body:data}),env,url);
for(const [action,verb] of [[7,'start'],[8,'stop']]){
 adminComment='/host '+verb+' sing-box-windows-lab';
 const request=winBytes(1,action);
 assert.equal(INFO(request).action,action,'strict Windows host action decode');
 response=await signedWindows(request);
 assert.equal(response.status,200,'fresh exact Windows '+verb+' signed by same Worker');
 // Correct action with a forged source comment must not receive authority.
 adminComment='/host '+(verb==='start'?'stop':'start')+' sing-box-windows-lab';
 response=await signedWindows(request);
 assert.equal(response.status,403,'Windows '+verb+' cannot reuse opposite comment');
}
adminComment='/host start sing-box-windows-lab';
// Field 12 is an appended, separately SYSTEM-signed native witness that the
// existing Worker signs ONLY inside the same approved Windows START intent.
// Worker validates bounded structure/identity/TTL; installed SYSTEM and
// Controller still verify the local signature and actual kernel snapshot.
const admissionBytes=({machine='sing-box-windows-lab',operation=info.id,
 desired=0xaa,signature=0x4d,observed=now-3,expires=now+45}={})=>CAT(
 FNUM(1,1),FLD(2,TE.encode(machine)),FLD(3,TE.encode(operation)),
 FLD(4,new Uint8Array(32).fill(0xbb)),
 FLD(5,new Uint8Array(32).fill(desired)),
 FLD(6,new Uint8Array(32).fill(0xcc)),
 FLD(7,new Uint8Array(32).fill(0xdd)),
 FNUM(8,observed),FNUM(9,expires),
 FLD(10,new Uint8Array(32).fill(0xee)),
 FLD(11,new Uint8Array(32).fill(0xab)),
 FLD(12,new Uint8Array(32).fill(0xcd)),
 FLD(13,new Uint8Array(64).fill(signature)));
const withAdmission=(proof,kind=1,action=7)=>CAT(winBytes(kind,action),FLD(12,proof));
const admitted=withAdmission(admissionBytes());
assert.equal(INFO(admitted).action,7,'Worker recognizes exact native Windows START extension');
response=await signedWindows(admitted);
assert.equal(response.status,200,'Worker accepts one fresh native-bound Windows START');
const admittedAuth=proofFields(new Uint8Array(await response.arrayBuffer()));
const admittedId=admittedAuth.get(2),admittedOp=admittedAuth.get(3);
const admittedPayload=CAT(TE.encode('sing-box/native-host-authorization/v1:'),
 U32(admitted.length),admitted,U32(admittedId.length),admittedId,
 U32(admittedOp.length),admittedOp,U64(admittedAuth.get(4)),U64(admittedAuth.get(5)));
assert.equal(await crypto.subtle.verify(
 'Ed25519',ed.publicKey,admittedAuth.get(6),admittedPayload),true,
 'Worker signature binds every byte of the nested native admission');
for(const [description,proof] of [
 ['wrong machine',admissionBytes({machine:'foreign-host'})],
 ['wrong operation',admissionBytes({operation:'issue1-comment-456'})],
 ['wrong desired ReleaseSet',admissionBytes({desired:0x52})],
 ['expired',admissionBytes({observed:now-70,expires:now-10})],
 ['future',admissionBytes({observed:now+1,expires:now+40})],
 ['too long TTL',admissionBytes({observed:now-20,expires:now+80})],
 ['zero signature',admissionBytes({signature:0})],
 ['truncated protobuf',admissionBytes().subarray(0,128)],
 ['unknown nested field',CAT(admissionBytes(),FNUM(14,1))],
 ['duplicate nested field',CAT(admissionBytes(),FLD(13,new Uint8Array(64).fill(1)))],
]){
 assert.equal(INFO(withAdmission(proof)),null,'invalid native admission '+description);
 assert.equal((await signedWindows(withAdmission(proof))).status,400,
  'Worker refuses '+description+' without signing');
}
assert.equal(INFO(withAdmission(admissionBytes(),2,7)),null,
 'VM START cannot use Windows native admission');
assert.equal(INFO(withAdmission(admissionBytes(),1,8)),null,
 'Windows STOP cannot reuse network capture authority');
assert.equal(INFO(CAT(admitted,FLD(12,admissionBytes()))),null,
 'duplicate native admission in the same HostIntent is invalid');
assert.equal(INFO(winBytes(2,7)),null,'VM cannot acquire Windows START authority');
assert.equal(INFO(winBytes(2,8)),null,'VM cannot acquire Windows STOP authority');
assert.equal(INFO(winBytes(1,9,1)),null,'Windows mode/TUN is not yet a signed Worker effect');
response=await signedWindows(winBytes(2,7));
assert.equal(response.status,400,'Worker rejects malformed VM START before GitHub GET');
adminComment=null;
// Signer failures must be bounded/typed; no private key or exception details.
response=await AUTHORIZE(await req(await jwt()),
 {...env,EDGE_HOST_SIGNING_PKCS8_BASE64:'INVALID-KEY'},url);
assert.equal(response.status,503);
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'HOST_SIGNER_KEY_INVALID');
assert.equal(await response.text(),'');
response=await AUTHORIZE(await req(await jwt()),
 {...env,EDGE_HOST_SIGNING_PKCS8_BASE64:Buffer.alloc(80,1).toString('base64url')},url);
assert.equal(response.status,503);
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'HOST_SIGNER_KEY_INVALID');
assert.equal(await response.text(),'');
// Exercise RFC8410 v1 and both RFC5958 v2 public-key wrappers. This
// test invokes the EXACT generated Worker source, never a duplicate parser.
const edPublic=new Uint8Array(await crypto.subtle.exportKey('raw',ed.publicKey));
const nodeV1=new Uint8Array(pkcs8);
assert.deepEqual([...nodeV1.slice(0,16)],
 [0x30,0x2e,0x02,0x01,0,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
const ringV2=CAT(Uint8Array.from([0x30,0x51,0x02,0x01,1]),
 nodeV1.slice(5),Uint8Array.from([0x81,0x21,0]),
 edPublic);
const earlyRingV2=CAT(Uint8Array.from([0x30,0x53,0x02,0x01,1]),
 nodeV1.slice(5),Uint8Array.from([0xa1,0x23,0x03,0x21,0]),
 edPublic);
for(const v2 of [ringV2,earlyRingV2]){
 response=await AUTHORIZE(await req(await jwt()),
  {...env,EDGE_HOST_SIGNING_PKCS8_BASE64:Buffer.from(v2).toString('base64url')},url);
 assert.equal(response.status,200,'verified v2 must normalize to same v1 mathematical key');
}
const badPublic=new Uint8Array(ringV2);badPublic[badPublic.length-1]^=1;
response=await AUTHORIZE(await req(await jwt()),
 {...env,EDGE_HOST_SIGNING_PKCS8_BASE64:Buffer.from(badPublic).toString('base64url')},url);
assert.equal(response.status,503,'v2 embedded public key mismatch must fail closed');
assert.equal(response.headers.get('X-Host-Authorization-Reason'),'HOST_SIGNER_KEY_MISMATCH');
for(const mutant of [
 CAT(ringV2,Uint8Array.of(0)),
 (()=>{const b=new Uint8Array(ringV2);b[0]=0x31;return b})(),
 (()=>{const b=new Uint8Array(ringV2);b[10]=0x2c;return b})(),
 (()=>{const b=new Uint8Array(ringV2);b[4]=0x00;return b})(),
]){
 response=await AUTHORIZE(await req(await jwt()),
  {...env,EDGE_HOST_SIGNING_PKCS8_BASE64:Buffer.from(mutant).toString('base64url')},url);
 assert.equal(response.status,503,'invalid ASN1 must fail closed');
 assert.equal(response.headers.get('X-Host-Authorization-Reason'),'HOST_SIGNER_KEY_INVALID');
}
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
assert.equal(response.headers.get('X-Host-Github-Stage'),'GITHUB_COMMENT');
assert.equal(response.headers.get('X-Host-Github-Kind'),'FETCH_EXCEPTION');
assert.equal(response.headers.get('X-Host-Github-Operation-Id'),info.id);
assert.equal(response.headers.get('X-Host-Github-Exception-Class'),'Error');
githubMode='http_release';
response=await AUTHORIZE(await req(await jwt()),env,url);
assert.equal(response.status,503);
assert.equal(response.headers.get('X-Host-Github-Stage'),'GITHUB_RELEASE');
assert.equal(response.headers.get('X-Host-Github-Kind'),'HTTP');
assert.equal(response.headers.get('X-Host-Github-Http-Status'),'429');
assert.equal(response.headers.get('X-Host-Github-Rate-Limit-Remaining'),'0');
assert.equal(response.headers.get('X-Host-Github-Retry-After'),'60');
assert.equal(response.headers.get('X-Host-Github-Request-Id'),'ABC-123');
assert.equal(response.headers.get('Location'),null,'no redirect authority forwarded');

githubMode='approved';appMode='valid';jwksMode='valid';
approvedAt=new Date((now-10)*1000).toISOString();
const nativeArgv=['/bin/sh','-c','id'];
const adminPayload={argv:nativeArgv,cwd:'/tmp',environment:['TEST_VALUE=ok'],
  stdin_base64:'aGVsbG8',timeout_seconds:40,publish_output:true};
adminComment='/host admin application-acceptance-2 '+ADMIN_ARGS_B64(adminPayload);
const commentHash=new Uint8Array(await crypto.subtle.digest('SHA-256',TE.encode(adminComment)));
const nativeBytes=CAT(FNUM(1,1),FLD(2,TE.encode('application-acceptance-2')),
  FNUM(3,6346290327),...nativeArgv.map(arg=>FLD(4,TE.encode(arg))),
  FLD(5,new Uint8Array(32).fill(0xaa)),FNUM(6,now),FLD(7,commentHash),
  FLD(8,TE.encode('/tmp')),FLD(9,TE.encode('TEST_VALUE=ok')),FLD(10,TE.encode('hello')),
  FNUM(11,40),FNUM(12,1));
assert.ok(ADMIN_INFO(nativeBytes),'no functional program allowlist in native contract');
assert.deepEqual(ADMIN_INFO(nativeBytes).argv,nativeArgv);
assert.equal(ADMIN_INFO(nativeBytes).cwd,'/tmp');
assert.equal(ADMIN_INFO(nativeBytes).publish,true);
const adminUrl=new URL('https://vm-worker.example/v1/host/admin/authorize');
const nativeReq=async (jwtValue,data)=>new Request(adminUrl,{
  method:'POST',headers:{'Cf-Access-Jwt-Assertion':jwtValue,
    'Content-Type':'application/x-protobuf'},body:data});
let adminResponse=await ADMIN_AUTHORIZE(await nativeReq(await jwt(),nativeBytes),env,adminUrl);
assert.equal(adminResponse.status,200,'exact approved administrator gets detached Worker signature');
assert.equal((await adminResponse.arrayBuffer()).byteLength>64,true,'nonempty signed protobuf');
let mutatedArgs=CAT(FNUM(1,1),FLD(2,TE.encode('application-acceptance-2')),
  FNUM(3,6346290327),FLD(4,TE.encode('/usr/bin/env')),FLD(4,TE.encode('sh')),
  FLD(5,new Uint8Array(32).fill(0xaa)),FNUM(6,now),FLD(7,commentHash),FNUM(11,300));
adminResponse=await ADMIN_AUTHORIZE(await nativeReq(await jwt(),mutatedArgs),env,adminUrl);
assert.equal(adminResponse.status,403,'admin source comment binds exact argv');
githubMode='denied';
adminResponse=await ADMIN_AUTHORIZE(await nativeReq(await jwt(),nativeBytes),env,adminUrl);
assert.equal(adminResponse.status,403,'unapproved GitHub actor cannot authorize root');
githubMode='approved';
// Windows uses the SAME VM Worker signing owner and native-admin domain.
// Exercise real router + GitHub approval, not merely a regex assertion.
const windowsArgv=[String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
  '-NoProfile','-NonInteractive','-Command','[Console]::WriteLine("synthetic")'];
const windowsCwd=String.raw`C:\Work`;
const windowsPayload={argv:windowsArgv,cwd:windowsCwd,environment:['TEST_VALUE=ok'],
  stdin_base64:'aGVsbG8',timeout_seconds:40,publish_output:true};
adminComment='/host admin sing-box-windows-lab '+ADMIN_ARGS_B64(windowsPayload);
const windowsCommentHash=new Uint8Array(await crypto.subtle.digest('SHA-256',TE.encode(adminComment)));
const windowsRequest=(cwd=windowsCwd)=>CAT(FNUM(1,1),FLD(2,TE.encode('sing-box-windows-lab')),
  FNUM(3,6346290327),...windowsArgv.map(arg=>FLD(4,TE.encode(arg))),
  FLD(5,new Uint8Array(32).fill(0xaa)),FNUM(6,now),FLD(7,windowsCommentHash),
  FLD(8,TE.encode(cwd)),FLD(9,TE.encode('TEST_VALUE=ok')),FLD(10,TE.encode('hello')),
  FNUM(11,40),FNUM(12,1));
const windowsBytes=windowsRequest();
assert.equal(ADMIN_INFO(windowsBytes).cwd,windowsCwd);
adminResponse=await ACTIVE_VM_WORKER.fetch(await nativeReq(await jwt(),windowsBytes),env);
assert.equal(adminResponse.status,200,'Windows request must reach the single signing owner');
const windowsAuth=proofFields(new Uint8Array(await adminResponse.arrayBuffer()));
const windowsKid=windowsAuth.get(2),windowsOp=windowsAuth.get(3);
const windowsSigned=CAT(TE.encode('sing-box/native-admin-authorization/v1:'),
  U32(windowsBytes.length),windowsBytes,U32(windowsKid.length),windowsKid,
  U32(windowsOp.length),windowsOp,U64(windowsAuth.get(4)),U64(windowsAuth.get(5)));
assert.equal(await crypto.subtle.verify('Ed25519',ed.publicKey,windowsAuth.get(6),windowsSigned),true,
  'Windows argv/cwd are cryptographically bound to the exact native request');
adminResponse=await ACTIVE_VM_WORKER.fetch(await nativeReq(await jwt(),windowsRequest(String.raw`C:\Other`)),env);
assert.equal(adminResponse.status,403,'different Windows cwd cannot reuse GitHub approval');
assert.equal(ADMIN_INFO(windowsRequest('relative')),null,'relative Windows cwd rejected before signing');
adminComment=null;githubMode='approved';
console.log('host_worker_access_contract=PASS');
"""
result=subprocess.run(["node","--input-type=module"],input=js+"\n"+fixture,
 text=True,capture_output=True,check=False,timeout=30)
if result.returncode:
    raise SystemExit("Worker host access fixture failed:\n"+result.stdout+"\n"+result.stderr)
print(result.stdout.strip())
