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
globalThis.fetch=async u=>{
  if(String(u)===expectedCertUrl) return Response.json({keys:[jwk]});
  if(String(u)==="https://api.github.com/repos/iamaman11/sing-box/issues/comments/123")
    return Response.json({
      user:{id:44100369},
      issue_url:"https://api.github.com/repos/iamaman11/sing-box/issues/1",
      created_at:new Date((now-2)*1000).toISOString(),
      updated_at:new Date((now-2)*1000).toISOString(),
      body:"/host apply vm-test-1",
    });
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
const empty=await call(intent,{});
requireTest(empty.status===404,"signer is not closed by default");
const wrong=await call(combine(intent,Buffer.from([0x50,1])));
requireTest(wrong.status!==200,"tampered protobuf must not be signed");
const expired=await call(intent,env,{exp:now-1});
requireTest(expired.status===403,"expired Cloudflare Access JWT accepted");
const wrongAud=await call(intent,env,{aud:["different-access-app"]});
requireTest(wrongAud.status===403,"wrong Access audience accepted");
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
const windowsSource=readFileSync(process.argv[2],"utf8").replace("const P=2;","const P=1;");
const tmpUrl="data:text/javascript;base64,"+Buffer.from(windowsSource).toString("base64");
const windows=await import(tmpUrl);
const winResult=await windows.default.fetch(new Request(
 "https://unit-test.workers.dev/v1/host/authorize",{
   method:"POST",headers:{"Content-Type":"application/x-protobuf"},body:intent,
 }),env);
requireTest(winResult.status===404,"Windows credential Worker must never sign Host requests");
console.log("worker Host authorization: Access RS256, exact approved SHA, Ed25519 Rust payload, TTL and single issuer PASS");
