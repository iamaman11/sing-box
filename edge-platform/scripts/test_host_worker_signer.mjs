#!/usr/bin/env node
// Pure offline cryptographic contract test for the EXISTING credential Worker.
// No Cloudflare API, private account, network request or host mutation.
import { webcrypto } from "node:crypto";
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";

const crypto = webcrypto;
const TE = new TextEncoder();
const domain = TE.encode("sing-box/native-host-authorization/v1:");
const encode64 = v => Buffer.from(v).toString("base64url");
const u32 = v => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; };
const u64 = v => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b; };
const combine = (...parts) => Buffer.concat(parts.map(x => Buffer.from(x)));
const varint = v => { let n = BigInt(v), a = []; do { let b = Number(n & 127n); n >>= 7n; if(n) b |= 128; a.push(b); } while(n); return Buffer.from(a); };
const field = (id, v) => combine(varint(BigInt(id)*8n + 2n), varint(v.length), v);
const number = (id, v) => combine(varint(BigInt(id)*8n), varint(v));
const decodeVarint = (b, at) => { let v=0n,shift=0n;for(let i=0;i<10;i++){if(at>=b.length)throw Error("truncated");const x=BigInt(b[at++]);v|=(x&127n)<<shift;if(!(x&128n))return [v,at];shift+=7n;}throw Error("oversized varint"); };
function fields(b){let p=0,out=new Map();while(p<b.length){let [k,a]=decodeVarint(b,p);p=a;const id=Number(k>>3n),wt=Number(k&7n);if(out.has(id))throw Error("duplicate field");if(wt===0){let [v,n]=decodeVarint(b,p);p=n;out.set(id,v);}else if(wt===2){let [v,n]=decodeVarint(b,p);p=n;const len=Number(v);if(len>b.length-p)throw Error("invalid len");out.set(id,b.subarray(p,p+len));p+=len;}else throw Error("unsupported wire");}return out;}
const requireTest = (ok,msg) => { if(!ok) throw Error(msg); };
const now=Math.floor(Date.now()/1000);
const rsa=await crypto.subtle.generateKey(
  {name:"RSASSA-PKCS1-v1_5",modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},true,["sign","verify"]);
const jwk=await crypto.subtle.exportKey("jwk",rsa.publicKey);jwk.kid="test-access-kid";
const issuer="https://unit-test.cloudflareaccess.com",aud="singbox-host-test-aud-01";
function jwt(claims={}) {
  // Separate async step below; JWT is not trusted merely because it decodes.
  return {h:encode64(TE.encode(JSON.stringify({alg:"RS256",kid:"test-access-kid"}))),
    p:encode64(TE.encode(JSON.stringify({iss:issuer,aud:[aud],nbf:now-2,exp:now+60,...claims})))};
}
async function accessToken(claims={}){
  const p=jwt(claims),payload=TE.encode(p.h+"."+p.p);
  const signature=await crypto.subtle.sign("RSASSA-PKCS1-v1_5",rsa.privateKey,payload);
  return p.h+"."+p.p+"."+encode64(signature);
}
const key=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
const pkcs8=await crypto.subtle.exportKey("pkcs8",key.privateKey);
const intent=combine(
 number(1,1),field(2,TE.encode("vm-test-1")),number(3,2),
 field(4,TE.encode("sing-box")),field(5,TE.encode("issue1-comment-123")),
 number(6,2),field(7,Buffer.alloc(32,1)),field(8,Buffer.alloc(32,2)),
 field(9,Buffer.alloc(32,3)),number(11,now)
);
const env={
 EDGE_HOST_SIGNING_PKCS8_BASE64:encode64(pkcs8),
 EDGE_HOST_SIGNING_KEY_ID:"vm-worker-key-v1",
 EDGE_HOST_GITHUB_ACTOR_ID:"44100369",
 EDGE_HOST_ACCESS_ISSUER:issuer,
 EDGE_HOST_ACCESS_AUD:aud,
};
const expectedCertUrl=issuer+"/cdn-cgi/access/certs";
let publishedRelease=true;
let approvedResource="sing-box",operatorComment="/host apply vm-test-1";
let commentCreated=now-2, receiptMerged=true, receiptBranchValid=true, mainMatched=true, receiptMergedAgo=20;
const testReleaseTag="edge-release-"+Buffer.alloc(32,3).toString("hex");
globalThis.fetch=async u=>{
  if(String(u)===expectedCertUrl) return Response.json({keys:[jwk]});
  if(String(u)==="https://api.github.com/repos/iamaman11/sing-box/issues/comments/123")
    return Response.json({
      user:{id:44100369},
      issue_url:"https://api.github.com/repos/iamaman11/sing-box/issues/1",
      created_at:new Date(commentCreated*1000).toISOString(),
      updated_at:new Date(commentCreated*1000).toISOString(),
      body:operatorComment+
        (approvedResource==="sing-box"?"":" "+approvedResource),
    });
  if(String(u)==="https://api.github.com/repos/iamaman11/sing-box/git/ref/heads/main")
    return Response.json({object:{type:"commit",sha:mainMatched?"a".repeat(40):"b".repeat(40)}});
  if(String(u)==="https://api.github.com/repos/iamaman11/sing-box/commits/"+"a".repeat(40)+"/pulls?per_page=20")
    return Response.json(receiptMerged?[{
      merged_at:new Date((now-receiptMergedAgo)*1000).toISOString(),draft:false,
      base:{ref:"main"},
      head:{repo:{full_name:"iamaman11/sing-box"},
            ref:receiptBranchValid?"host-receipt-vm-test-1-123":"host-receipt-other-123"},
      merge_commit_sha:"a".repeat(40),
      title:"host: register native receipt for vm-test-1"
    }]:[]);
  if(String(u)==="https://api.github.com/repos/iamaman11/sing-box/releases/tags/"+testReleaseTag)
    return publishedRelease
      ? Response.json({tag_name:testReleaseTag,draft:false,prerelease:false,
          target_commitish:"a".repeat(40)})
      : new Response(null,{status:404});
  throw Error("unexpected external lookup "+String(u));
};
const mod=await import(pathToFileURL(process.argv[2]).href);
async function call(body= intent, settings=env, claims={}){
  const token=await accessToken(claims);
  const headers={"Content-Type":"application/x-protobuf","Cf-Access-Jwt-Assertion":token};
  const req=new Request("https://unit-test.workers.dev/v1/host/authorize",
    {method:"POST",headers,body});
  return mod.default.fetch(req,settings);
}
// A live signing-key identity proof is deliberately not an authorization.
// This must exercise the exact compiled Worker source with a random challenge.
const identityNonce=Buffer.alloc(32,0x5c);
async function identityProof(signerEnv=env,nonce=identityNonce,claims={}){
 const token=await accessToken(claims);
 const url="https://unit-test.workers.dev/v1/host/identity?challenge="+Buffer.from(nonce).toString("hex");
 return mod.default.fetch(new Request(url,{headers:{"Cf-Access-Jwt-Assertion":token}}),signerEnv);
}
const identityResponse=await identityProof();
requireTest(identityResponse.status===200,"active signer identity cannot be attested");
requireTest(identityResponse.headers.get("X-Host-Authorization-Scope")==="SIGNED_IDENTITY_NO_MUTATION",
 "signed identity is not a non-mutating scope");
const identity=fields(Buffer.from(await identityResponse.arrayBuffer()));
const identityPublic=Buffer.from(identity.get(3));
const expectedPublic=Buffer.from(await crypto.subtle.exportKey("raw",key.publicKey));
requireTest(identity.get(1)===1n&&identityPublic.equals(expectedPublic),
 "identity proof did not expose the ACTIVE signing key");
requireTest(Buffer.from(identity.get(2)).equals(identityNonce),"challenge not bound");
const identityKey=Buffer.from(identity.get(4));
const identityPayload=combine(TE.encode("sing-box/host-signer-identity/v1:"),
 identityNonce,identityPublic,u32(identityKey.length),identityKey,u64(identity.get(5)));
requireTest(await crypto.subtle.verify("Ed25519",key.publicKey,identity.get(6),identityPayload),
 "identity proof signature mismatch");
requireTest(!(await crypto.subtle.verify("Ed25519",key.publicKey,identity.get(6),
 combine(TE.encode("sing-box/host-signer-identity/v1:"),
 Buffer.alloc(32,0x5d),identityPublic,u32(identityKey.length),identityKey,u64(identity.get(5))))),
 "challenge replay accepted");
requireTest((await identityProof(env,identityNonce,{aud:["wrong-audience"]})).status===403,
 "foreign Cloudflare Access identity accepted");
requireTest((await identityProof({...env,EDGE_HOST_SIGNING_PKCS8_BASE64:"invalid"})).status===503,
 "identity proof accepted invalid signer");
const missingNonce=await mod.default.fetch(
 new Request("https://unit-test.workers.dev/v1/host/identity"),env);
requireTest(missingNonce.status===404,"identity challenge is optional");
const empty=await call(intent,{});
requireTest(empty.status===404,"signer is not closed by default");
const duplicateDigest=await call(combine(intent,field(7,Buffer.alloc(32,4))));
requireTest(duplicateDigest.status===400,"duplicate protobuf digest accepted");
const missingRelease=combine(
 number(1,1),field(2,TE.encode("vm-test-1")),number(3,2),
 field(4,TE.encode("sing-box")),field(5,TE.encode("issue1-comment-123")),
 number(6,2),field(7,Buffer.alloc(32,1)),field(8,Buffer.alloc(32,2)),
 number(11,now));
requireTest((await call(missingRelease)).status===400,"missing release digest accepted");
const zeroDigest=combine(
 number(1,1),field(2,TE.encode("vm-test-1")),number(3,2),
 field(4,TE.encode("sing-box")),field(5,TE.encode("issue1-comment-123")),
 number(6,2),field(7,Buffer.alloc(32)),field(8,Buffer.alloc(32,2)),
 field(9,Buffer.alloc(32,3)),number(11,now));
requireTest((await call(zeroDigest)).status===400,"zero registry digest accepted");
const explicitZeroMode=combine(intent,number(10,0));
requireTest((await call(explicitZeroMode)).status===400,"noncanonical zero mode accepted");
const reorderedFields=combine(
 field(2,TE.encode("vm-test-1")),number(1,1),number(3,2),
 field(4,TE.encode("sing-box")),field(5,TE.encode("issue1-comment-123")),
 number(6,2),field(7,Buffer.alloc(32,1)),field(8,Buffer.alloc(32,2)),
 field(9,Buffer.alloc(32,3)),number(11,now));
requireTest((await call(reorderedFields)).status===400,"out-of-order protobuf accepted");
const wrong=await call(combine(intent,Buffer.from([0x50,1])));
requireTest(wrong.status!==200,"tampered protobuf must not be signed");
const expired=await call(intent,env,{exp:now-1});
requireTest(expired.status===403,"expired Cloudflare Access JWT accepted");
const wrongAud=await call(intent,env,{aud:["different-access-app"]});
requireTest(wrongAud.status===403,"wrong Access audience accepted");
const wrongScalarAud=await call(intent,env,{aud:"different-access-app"});
requireTest(wrongScalarAud.status===403,"wrong string Access audience accepted");
const malformedAud=await call(intent,env,{aud:[aud,42]});
requireTest(malformedAud.status===403,"mixed-type audience array accepted");
const validScalarAud=await call(intent,env,{aud});
requireTest(validScalarAud.status===200,"exact string JWT audience rejected");
publishedRelease=false;
requireTest((await call()).status===403,"unpublished ReleaseSet was authorized");
publishedRelease=true;
const response=await call();
requireTest(response.status===200,"valid exact signed request rejected: "+response.status);
const raw=Buffer.from(await response.arrayBuffer());
const parsed=fields(raw);
requireTest(parsed.get(1)===1n,"authorization schema mismatch");
const keyId=Buffer.from(parsed.get(2)),operation=Buffer.from(parsed.get(3));
const issued=parsed.get(4),expires=parsed.get(5),signature=parsed.get(6);
requireTest(operation.toString()==="issue1-comment-123","operation identity mismatch");
requireTest(expires-issued===120n,"Host signer TTL mismatch");
const payload=combine(domain,u32(intent.length),intent,u32(keyId.length),keyId,
 u32(operation.length),operation,u64(issued),u64(expires));
requireTest(await crypto.subtle.verify("Ed25519",key.publicKey,signature,payload),
 "Worker signature does not verify against the exact Rust domain-separated payload");
// A five-minute comment is NOT a deployment deadline: the protected merge
// is the separate immutable proof for precisely this pending first-use VM.
commentCreated=now-3600;
requireTest((await call()).status===200,"protected receipt merge did not admit delayed first-use");
receiptBranchValid=false;
requireTest((await call()).status===403,"foreign receipt PR authorized an old comment");
receiptBranchValid=true;
mainMatched=false;
requireTest((await call()).status===403,"non-current protected main signed old comment");
mainMatched=true;
receiptMerged=false;
requireTest((await call()).status===403,"old comment signed without receipt merge proof");
receiptMerged=true;
receiptMergedAgo=90000;
requireTest((await call()).status===403,"expired receipt merge proof authorized old comment");
receiptMergedAgo=20;
commentCreated=now-2;
// v1 signature domain binds the exact protobuf bytes, including the scope.
const scopedId="config/vultr-edge/line2-proxy";
const scopedIntent=combine(
 number(1,1),field(2,TE.encode("vm-test-1")),number(3,2),
 field(4,TE.encode(scopedId)),field(5,TE.encode("issue1-comment-123")),
 number(6,2),field(7,Buffer.alloc(32,1)),field(8,Buffer.alloc(32,2)),
 field(9,Buffer.alloc(32,3)),number(11,now)
);
requireTest((await call(scopedIntent)).status===403,
  "scoped request signed without exact GitHub comment");
approvedResource=scopedId;
commentCreated=now-3600;
requireTest((await call(scopedIntent)).status===403,
 "delayed receipt merge proof authorized an old scoped config comment");
commentCreated=now-2;
const scopedResponse=await call(scopedIntent);
requireTest(scopedResponse.status===200,"approved config resource signature rejected");
const scopedParsed=fields(Buffer.from(await scopedResponse.arrayBuffer()));
const scopedKid=Buffer.from(scopedParsed.get(2)),scopedOp=Buffer.from(scopedParsed.get(3));
const scopedPayload=combine(domain,u32(scopedIntent.length),scopedIntent,
 u32(scopedKid.length),scopedKid,u32(scopedOp.length),scopedOp,
 u64(scopedParsed.get(4)),u64(scopedParsed.get(5)));
requireTest(await crypto.subtle.verify("Ed25519",key.publicKey,
 scopedParsed.get(6),scopedPayload), "resource scope omitted from signature");
requireTest((await call(combine(scopedIntent,field(4,TE.encode("sing-box"))))).status===400,
  "duplicate protobuf resource scope accepted");
approvedResource="sing-box";
requireTest((await call(scopedIntent)).status===403,
  "scoped request signed after GitHub comment changed");
const badScope=combine(
 number(1,1),field(2,TE.encode("vm-test-1")),number(3,2),
 field(4,TE.encode("container/vultr-edge/line2-proxy")),
 field(5,TE.encode("issue1-comment-123")),number(6,2),
 field(7,Buffer.alloc(32,1)),field(8,Buffer.alloc(32,2)),
 field(9,Buffer.alloc(32,3)),number(11,now)
);
requireTest((await call(badScope)).status===400,
  "arbitrary container scope accepted by config-only Worker");
// Native historical adjudication reuses signed FleetHostAction::Recover,
// but operator authorization must match the exact --adjudicate syntax.
const recoverIntent=combine(
 number(1,1),field(2,TE.encode("vm-test-1")),number(3,2),
 field(4,TE.encode("sing-box")),field(5,TE.encode("issue1-comment-123")),
 number(6,3),field(7,Buffer.alloc(32,1)),field(8,Buffer.alloc(32,2)),
 field(9,Buffer.alloc(32,3)),number(11,now)
);
operatorComment="/host recover vm-test-1 --adjudicate";
requireTest((await call(recoverIntent)).status===200,
 "signed VM adjudication rejected despite exact GitHub approval");
operatorComment="/host recover vm-test-1";
requireTest((await call(recoverIntent)).status===403,
 "VM adjudication authorized by ordinary code-only recover command");
operatorComment="/host apply vm-test-1";
requireTest((await call(recoverIntent)).status===403,
 "VM adjudication authorized by different APPLY command");
requireTest((await call(intent)).status===200,
 "normal APPLY no longer authorized after adjudication contract");
const windowsSource=readFileSync(process.argv[2],"utf8").replace("const P=2;","const P=1;");
const tmpUrl="data:text/javascript;base64,"+Buffer.from(windowsSource).toString("base64");
const windows=await import(tmpUrl);
const winResult=await windows.default.fetch(new Request(
 "https://unit-test.workers.dev/v1/host/authorize",{
   method:"POST",headers:{"Content-Type":"application/x-protobuf"},body:intent,
 }),env);
requireTest(winResult.status===404,"Windows credential Worker must never sign Host requests");
console.log("worker Host authorization: Access RS256, exact approved SHA, Ed25519 Rust payload, TTL and single issuer PASS");
