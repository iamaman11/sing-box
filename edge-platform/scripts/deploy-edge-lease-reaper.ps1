param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$WslDistribution = "Ubuntu",
    [string]$VaultPath = "/home/bose/projects/secret-vault/bin/secret-vault",
    [string]$WorkerVaultRecord = "cloudflare.singbox-lease-reaper-worker-deploy",
    [string]$VultrVaultRecord = "vultr.singbox-lifecycle",
    [string]$DnsVaultRecord = "cloudflare.singbox-dns-deploy",
    [string]$LeaseAuthVaultRecord = "edge.lease-reaper-auth"
)

$ErrorActionPreference = "Stop"
$workerSourcePath = Join-Path $RepoRoot "edge-platform\workers\edge-lease-reaper\src\index.js"
if (-not (Test-Path $workerSourcePath)) { throw "Worker source not found: $workerSourcePath" }
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$runtimeConfig = Join-Path $runtimeDir "lease-reaper.json"
function ConvertTo-WslPath {
    param([string]$Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -notmatch '^[A-Za-z]:\\') { throw "Only drive-letter Windows paths are supported: $fullPath" }
    $drive = $fullPath.Substring(0, 1).ToLowerInvariant()
    return "/mnt/$drive/" + $fullPath.Substring(3).Replace('\', '/')
}
$wslWorkerSourcePath = ConvertTo-WslPath $workerSourcePath
$wslRuntimeConfig = ConvertTo-WslPath $runtimeConfig

$taskCode = @'
import http.client, json, os, socket, ssl, sys
ACCOUNT='4426df1449e417511bc7697d60b7f62f'
WORKER='edge-lease-reaper'
NAMESPACE_TITLE='edge-lease-reaper'
ZONE_ID='ec445527b8dd85a39fd74aee3ef968f4'
DNS_NAME='edge.alegria.by'
class CFConnection(http.client.HTTPSConnection):
  def connect(self):
    last_error=None
    for candidate in socket.getaddrinfo('api.cloudflare.com',443,socket.AF_INET,socket.SOCK_STREAM):
      try:
        raw=socket.create_connection(candidate[4],10)
        self.sock=self._context.wrap_socket(raw,server_hostname='api.cloudflare.com')
        return
      except OSError as error:
        last_error=error
    raise last_error or OSError('No Cloudflare API address was reachable')
def api(method,path,body=None,content_type='application/json'):
  c=CFConnection('api.cloudflare.com',timeout=30,context=ssl.create_default_context())
  c.request(method,path,body=body,headers={'Authorization':'Bearer '+os.environ['CF_WORKER_TOKEN'],'Content-Type':content_type})
  r=c.getresponse(); raw=r.read().decode(); c.close()
  try: payload=json.loads(raw)
  except: payload={'success':False,'raw':raw}
  if r.status>=300 or not payload.get('success',False): raise RuntimeError('Cloudflare API '+str(r.status)+': '+json.dumps(payload))
  return payload.get('result')
namespaces=api('GET',f'/client/v4/accounts/{ACCOUNT}/storage/kv/namespaces?per_page=1000')
matches=[x for x in namespaces if x.get('title')==NAMESPACE_TITLE]
if len(matches)>1: raise RuntimeError('more than one lease-reaper KV namespace exists')
namespace_id=matches[0]['id'] if matches else api('POST',f'/client/v4/accounts/{ACCOUNT}/storage/kv/namespaces',json.dumps({'title':NAMESPACE_TITLE}),'application/json')['id']
source=open(os.environ['WORKER_SOURCE_PATH'],'r',encoding='utf-8').read()
metadata={'main_module':'worker.js','compatibility_date':'2026-08-29','bindings':[
  {'type':'kv_namespace','name':'EDGE_LEASES','namespace_id':namespace_id},
  {'type':'plain_text','name':'CF_ZONE_ID','text':ZONE_ID},
  {'type':'plain_text','name':'CF_DNS_NAME','text':DNS_NAME},
]}
boundary='----edgelease'+str(os.getpid())
multipart='\r\n'.join([
  '--'+boundary,'Content-Disposition: form-data; name="metadata"','Content-Type: application/json','',json.dumps(metadata),
  '--'+boundary,'Content-Disposition: form-data; name="worker.js"; filename="worker.js"','Content-Type: application/javascript+module','',source,
  '--'+boundary+'--',''
]).encode('utf-8')
api('PUT',f'/client/v4/accounts/{ACCOUNT}/workers/scripts/{WORKER}',multipart,'multipart/form-data; boundary='+boundary)
for name, value in [('VULTR_API_KEY',os.environ['VULTR_API_KEY']),('CLOUDFLARE_DNS_TOKEN',os.environ['CF_DNS_TOKEN']),('LEASE_AUTH_TOKEN',os.environ['LEASE_AUTH_TOKEN'])]:
  api('PUT',f'/client/v4/accounts/{ACCOUNT}/workers/scripts/{WORKER}/secrets',json.dumps({'name':name,'text':value,'type':'secret_text'}),'application/json')
api('PUT',f'/client/v4/accounts/{ACCOUNT}/workers/scripts/{WORKER}/schedules',json.dumps([{'cron':'*/15 * * * *'}]),'application/json')
result={'worker_name':WORKER,'worker_url':'https://lease.alegria.by','kv_namespace_id':namespace_id,'schedule':'*/15 * * * *','lease_minutes':60,'grace_minutes':30}
with open(os.environ['RUNTIME_CONFIG_PATH'],'w',encoding='utf-8') as f: json.dump(result,f,indent=2); f.write('\n')
print(json.dumps({'deployed':True,'worker_name':WORKER,'worker_url':result['worker_url'],'schedule':result['schedule']}))
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($taskCode))
$runner = "import base64;exec(base64.b64decode('$encoded'))"
$oldWslenv = $env:WSLENV
$env:WORKER_SOURCE_PATH = $wslWorkerSourcePath
$env:RUNTIME_CONFIG_PATH = $wslRuntimeConfig
$env:WSLENV = "WORKER_SOURCE_PATH:RUNTIME_CONFIG_PATH"
try {
    & wsl.exe -d $WslDistribution -- $VaultPath run $WorkerVaultRecord CF_WORKER_TOKEN -- $VaultPath run $VultrVaultRecord VULTR_API_KEY -- $VaultPath run $DnsVaultRecord CF_DNS_TOKEN -- $VaultPath run $LeaseAuthVaultRecord LEASE_AUTH_TOKEN -- python3 -c $runner
    if ($LASTEXITCODE -ne 0) { throw "Cloudflare Worker deployment failed" }
} finally {
    $env:WSLENV = $oldWslenv
    Remove-Item Env:WORKER_SOURCE_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:RUNTIME_CONFIG_PATH -ErrorAction SilentlyContinue
}
