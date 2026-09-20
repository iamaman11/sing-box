#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESOLVER = ROOT / "scripts" / "resolve_durable_release.sh"

FAKE_GH = """#!/usr/bin/env python3
import json, os, re, sys
from pathlib import Path
s=json.loads(Path(os.environ["FAKE_GITHUB_STATE"]).read_text())
a=sys.argv[1:]
assert a and a[0]=="api"
e=a[-1]
repo="iamaman11/sing-box"
if e.startswith(f"repos/{repo}/releases?"):
    page=int(dict(x.split("=",1) for x in e.split("?",1)[1].split("&")).get("page","1"))
    print(json.dumps(s["releases"] if page==1 else []))
elif e.startswith(f"repos/{repo}/git/ref/tags/"):
    tag=e.rsplit("/",1)[1]; sha=s["tag_refs"][tag]
    print(json.dumps({"object":{"type":"commit","sha":sha}}))
elif re.fullmatch(rf"repos/{repo}/releases/\\d+",e):
    rid=int(e.rsplit("/",1)[1]); print(json.dumps(next(x for x in s["releases"] if x["id"]==rid)))
elif e.startswith(f"repos/{repo}/git/commits/"):
    sha=e.rsplit("/",1)[1]; print(json.dumps({"tree":{"sha":s["commit_trees"][sha]}}))
else:
    raise SystemExit("unsupported gh endpoint: "+e)
"""

FAKE_CURL = """#!/usr/bin/env python3
import base64, json, os, re, sys
from pathlib import Path
s=json.loads(Path(os.environ["FAKE_GITHUB_STATE"]).read_text())
a=sys.argv[1:]; out=Path(a[a.index("--output")+1]); url=a[-1]
m=re.fullmatch(r"https://api\\.github\\.com/repos/iamaman11/sing-box/releases/assets/(\\d+)",url)
assert m
aid=int(m.group(1)); data=base64.b64decode(s["asset_bytes"][str(aid)])
if s.get("corrupt_asset_id")==aid: data+=b"x"
out.write_bytes(data)
"""

def sha(data):
    return hashlib.sha256(data).hexdigest()

def exe(path, content):
    path.write_text(content); path.chmod(path.stat().st_mode | stat.S_IXUSR)

def make_state(accepted_override=None, ambiguous=False):
    accepted="a"*40; candidate="b"*40; tree="c"*40
    pb=b"release-set-v2"; pbsha=sha(pb); tag="edge-release-"+pbsha
    agent=b"agent"; controller=b"controller"; asha=sha(agent); csha=sha(controller)
    verifier=f"""#!/usr/bin/env python3
import hashlib,sys
a=sys.argv[1:]; assert a[0]=="verify-vm"; d=dict(zip([x[2:] for x in a[1::2]],a[2::2]))
assert d["source-revision"]=="{candidate}"
def h(p): return hashlib.sha256(open(p,"rb").read()).hexdigest()
assert h(d["edge-agent"])=="{asha}"
assert h(d["edge-controller"])=="{csha}"
assert h(d["input"])=="{pbsha}"
print("release_set_sha256={pbsha}")
print("schema_version=2")
print("source_revision={candidate}")
print("edge_agent_sha256={asha}")
print("edge_controller_sha256={csha}")
print("sing_box_image=ghcr.io/iamaman11/vultr-edge-gateway@sha256:"+"1"*64)
print("warp_egress_image=ghcr.io/iamaman11/vultr-warp-egress@sha256:"+"2"*64)
print("mesh_image=docker.io/cloudflare/mesh@sha256:"+"3"*64)
""".encode()
    acceptance=(json.dumps({"schema":1,"accepted_revision":accepted_override or accepted,
      "candidate_revision":candidate,"source_tree":tree,"candidate_run_id":123})+"\n").encode()
    files={
      "acceptance.json":acceptance,
      "edge-agent-linux-amd64":agent,
      "edge-agent-linux-amd64.sha256":f"{asha}  edge-agent-linux-amd64\n".encode(),
      "edge-controller-linux-amd64":controller,
      "edge-controller-linux-amd64.sha256":f"{csha}  edge-controller-linux-amd64\n".encode(),
      "edge-platform-windows.zip":b"w",
      "edge-platform-windows.zip.sha256":f"{sha(b'w')}  edge-platform-windows.zip\n".encode(),
      "edge-release-set-linux-amd64":verifier,
      "edge-release-set-linux-amd64.sha256":f"{sha(verifier)}  edge-release-set-linux-amd64\n".encode(),
      "release-set.pb":pb,
      "release-set.pb.sha256":f"{pbsha}  release-set.pb\n".encode(),
    }
    assets=[]; blobs={}
    for i,(name,data) in enumerate(files.items(),700000001):
      assets.append({"id":i,"name":name,"size":len(data),"digest":"sha256:"+sha(data)})
      blobs[str(i)]=base64.b64encode(data).decode()
    release={"id":500000001,"tag_name":tag,"draft":False,"prerelease":False,"assets":assets}
    releases=[release]; refs={tag:accepted}
    if ambiguous:
      tag2="edge-release-"+"d"*64
      releases.append({"id":500000002,"tag_name":tag2,"draft":False,"prerelease":False,"assets":assets})
      refs[tag2]=accepted
    state={"releases":releases,"tag_refs":refs,"commit_trees":{accepted:tree,candidate:tree},"asset_bytes":blobs}
    meta={"accepted":accepted,"candidate":candidate,"tree":tree,"tag":tag,"pbsha":pbsha,"asha":asha,"csha":csha,
      "controller_id":next(x["id"] for x in assets if x["name"]=="edge-controller-linux-amd64")}
    return state,meta

def run(state,meta,expected=None,ok=False):
    with tempfile.TemporaryDirectory() as td:
      root=Path(td); bindir=root/"bin"; bindir.mkdir()
      exe(bindir/"gh",FAKE_GH); exe(bindir/"curl",FAKE_CURL)
      sp=root/"state.json"; sp.write_text(json.dumps(state))
      out=root/"out"; env=os.environ.copy()
      env.update({"GH_TOKEN":"x","REPOSITORY":"iamaman11/sing-box","ACCEPTED_REVISION":meta["accepted"],
        "OUTPUT_DIR":str(out),"FAKE_GITHUB_STATE":str(sp),"PATH":str(bindir)+os.pathsep+env["PATH"]})
      if expected: env["EXPECTED_RELEASE_TAG"]=expected
      p=subprocess.run(["bash",str(RESOLVER)],env=env,text=True,capture_output=True)
      if ok:
        assert p.returncode==0,(p.stdout,p.stderr)
        vals=dict(x.split("=",1) for x in (out/"resolved.env").read_text().splitlines())
        assert vals["EDGE_RELEASE_TAG"]==meta["tag"]
        assert vals["EDGE_RELEASE_SET_SHA256"]==meta["pbsha"]
        assert vals["EDGE_CONTROLLER_SHA256"]==meta["csha"]
        assert vals["EDGE_AGENT_SHA256"]==meta["asha"]
      else:
        assert p.returncode!=0,p.stdout

def main():
    s,m=make_state(); run(s,m,expected=m["tag"],ok=True)
    s,m=make_state(ambiguous=True); run(s,m)
    s,m=make_state(accepted_override="e"*40); run(s,m)
    s,m=make_state(); run(s,m,expected="edge-release-"+"f"*64)
    s,m=make_state(); s["corrupt_asset_id"]=m["controller_id"]; run(s,m)
    print("durable release resolver tests: OK")

if __name__=="__main__":
    main()
