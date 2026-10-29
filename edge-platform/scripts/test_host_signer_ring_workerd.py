#!/usr/bin/env python3
"""Run EXACT production signer helper in pinned local workerd with ephemeral ring v2.

A Rust ring 0.17.14 example creates the synthetic key. No production secret,
remote endpoint, deployment, network egress or persistent private key.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

assert len(sys.argv) == 2, "ephemeral ring fixture path required"
fixture_path = Path(sys.argv[1])
fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
assert set(fixture) == {"ring_pkcs8_v2", "public_key"}
source = Path("edge-platform/crates/edge-orchestrator/src/cloudflare_credential_plane_command.rs").read_text(encoding="utf-8")
start, end = 'let source = r#"', '"#\n        .replace("__PROJECTION__"'
assert source.count(start) == source.count(end) == 1
worker = source.split(start, 1)[1].split(end, 1)[0]
assert worker.count("function B64(") == worker.count("function U32(") == worker.count("function CAT(") == worker.count("function VI(") == 1
crypto_helpers = worker[worker.index("function B64("):worker.index("function U32(")]
concat = worker[worker.index("function CAT("):worker.index("function VI(")]
assert "async function HOST_SIGNER_SIGN(" in crypto_helpers
assert "function HOST_SIGNER_PKCS8(" in crypto_helpers
js = """
// This snippet is extracted from the generated production Worker, NOT copied.
""" + crypto_helpers + concat + """
function BASE64URL(b){
 let text="";for(const byte of b)text+=String.fromCharCode(byte);
 return btoa(text).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"");
}
export default {async fetch(q){
 if(q.method!=="POST")return new Response(null,{status:405});
 try{
  const f=await q.json();
  const input=B64(f.ring_pkcs8_v2),publicKey=B64(f.public_key);
  if(!input||!publicKey||publicKey.length!==32)return new Response(null,{status:500});
  const normalized=HOST_SIGNER_PKCS8(input);
  if(!normalized||normalized.v1.length!==48||!normalized.publicKey)return new Response(null,{status:500});
  if(!normalized.publicKey.every((v,i)=>v===publicKey[i]))return new Response(null,{status:500});
  // The live identity endpoint must be able to derive ONLY the public key
  // from the same ring PKCS8, on real pinned workerd (not just Node WebCrypto).
  const pubKey=await crypto.subtle.importKey("pkcs8",normalized.v1,{name:"Ed25519"},true,["sign"]);
  const jwk=await crypto.subtle.exportKey("jwk",pubKey);
  if(jwk.kty!=="OKP"||jwk.crv!=="Ed25519"||!jwk.x)return new Response(null,{status:500});
  const derived=B64(jwk.x);
  if(!derived||derived.length!==32||!derived.every((v,i)=>v===publicKey[i]))
    return new Response(null,{status:500});
  const payload=new TextEncoder().encode("sing-box/ring-workerd-test/v1");
  const result=await HOST_SIGNER_SIGN(f.ring_pkcs8_v2,payload);
  if(!result.signature||result.reason)return new Response(null,{status:500});
  const verify=await crypto.subtle.importKey("raw",publicKey,{name:"Ed25519"},false,["verify"]);
  if(!await crypto.subtle.verify("Ed25519",verify,result.signature,payload))return new Response(null,{status:500});
  const corrupt=input.slice();corrupt[corrupt.length-1]^=1;
  const mismatched=await HOST_SIGNER_SIGN(BASE64URL(corrupt),payload);
  if(mismatched.reason!=="HOST_SIGNER_KEY_MISMATCH")return new Response(null,{status:500});
  const trailing=new Uint8Array(input.length+1);trailing.set(input);
  if((await HOST_SIGNER_SIGN(BASE64URL(trailing),payload)).reason!=="HOST_SIGNER_KEY_INVALID")return new Response(null,{status:500});
  return new Response(null,{status:204});
 }catch{return new Response(null,{status:500})}
}};
"""
# Workerd is LOCAL and isolated from all Cloudflare secrets/accounts.
with tempfile.TemporaryDirectory(prefix="singbox-workerd-contract-") as t:
    d = Path(t)
    (d / "worker.mjs").write_text(js, encoding="utf-8")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    capnp = """using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
 services = [(name = "main", worker = .contractWorker)],
 sockets = [(name = "http", address = "127.0.0.1:%d", http = (), service = "main")]
);
const contractWorker :Workerd.Worker = (
 modules = [(name = "worker", esModule = embed "worker.mjs")],
 compatibilityDate = "2026-08-11"
);
""" % port
    (d / "config.capnp").write_text(capnp, encoding="utf-8")
    cmd = ["npm", "exec", "--yes", "--package=workerd@1.20261015.1", "--",
           "workerd", "serve", "config.capnp"]
    proc = subprocess.Popen(cmd, cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        passed = False
        for _ in range(80):
            if proc.poll() is not None:
                break
            try:
                request = urllib.request.Request(
                    "http://127.0.0.1:%d/" % port,
                    data=json.dumps(fixture).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    passed = response.status == 204
                break
            except (OSError, TimeoutError):
                time.sleep(0.5)
        if not passed:
            raise SystemExit("ring generated v2 -> production Worker signer in pinned workerd: FAIL")
    finally:
        # A successful 'serve' is long-lived: never wait for it implicitly.
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
print("ring_pkcs8_v2_to_pinned_workerd_sign_verify=PASS")
