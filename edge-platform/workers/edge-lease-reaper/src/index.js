const LEASE_KEY = "active-edge";
const MAX_LEASE_MS = 75 * 60 * 1000;
const MIN_LEASE_MS = 15 * 60 * 1000;
const REAP_GRACE_MS = 30 * 60 * 1000;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function authorized(request, env) {
  const value = request.headers.get("authorization") || "";
  return value === `Bearer ${env.LEASE_AUTH_TOKEN}`;
}

function validIpv4(value) {
  const parts = String(value || "").split(".");
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function validInstanceId(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value || ""));
}

async function renew(request, env) {
  if (!authorized(request, env)) return json({ error: "unauthorized" }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  const expiresAt = Date.parse(body.expiresAt || "");
  const delta = expiresAt - Date.now();
  if (!validInstanceId(body.instanceId) || !validIpv4(body.ip) || !Number.isFinite(expiresAt) || delta < MIN_LEASE_MS || delta > MAX_LEASE_MS) {
    return json({ error: "invalid lease" }, 400);
  }

  const lease = {
    instanceId: body.instanceId,
    ip: body.ip,
    expiresAt: new Date(expiresAt).toISOString(),
    renewedAt: new Date().toISOString(),
  };
  await env.EDGE_LEASES.put(LEASE_KEY, JSON.stringify(lease));
  return json({ ok: true, expiresAt: lease.expiresAt });
}

async function requestShutdown(request, env, ctx) {
  if (!authorized(request, env)) return json({ error: "unauthorized" }, 401);
  const raw = await env.EDGE_LEASES.get(LEASE_KEY);
  if (!raw) return json({ ok: true, action: "no active lease" }, 202);
  let lease;
  try {
    lease = JSON.parse(raw);
  } catch {
    await env.EDGE_LEASES.delete(LEASE_KEY);
    return json({ ok: true, action: "invalid lease discarded" }, 202);
  }
  lease.shutdownRequestedAt = new Date().toISOString();
  await env.EDGE_LEASES.put(LEASE_KEY, JSON.stringify(lease));
  // Returning immediately gives Windows time to finish shutdown. The Worker
  // continues the provider call independently and cron retries if it fails.
  ctx.waitUntil(reap(env, true)
    .then((result) => console.log(JSON.stringify(result)))
    .catch((error) => console.error(`shutdown reap failed: ${error.message}`)));
  return json({ ok: true, action: "shutdown deletion accepted" }, 202);
}

async function status(request, env) {
  if (!authorized(request, env)) return json({ error: "unauthorized" }, 401);
  const raw = await env.EDGE_LEASES.get(LEASE_KEY);
  if (!raw) return json({ ok: true, lease: "absent" });
  try {
    const lease = JSON.parse(raw);
    const response = {
      ok: true,
      lease: "present",
      instanceId: lease.instanceId,
      ip: lease.ip,
      expiresAt: lease.expiresAt,
      shutdownRequestedAt: lease.shutdownRequestedAt || null,
    };
    const lookup = await fetch(`https://api.vultr.com/v2/instances/${lease.instanceId}`, {
      headers: {
        Authorization: `Bearer ${env.VULTR_API_KEY}`,
        Accept: "application/json",
        "User-Agent": "curl/8.0",
      },
    });
    const unauthenticatedProbe = await fetch(`https://api.vultr.com/v2/instances/${lease.instanceId}`);
    response.vultrUnauthenticatedLookup = unauthenticatedProbe.status;
    response.vultrLookup = lookup.status;
    if (!lookup.ok) {
      response.vultrError = (await lookup.text()).slice(0, 300);
      response.vultrResponseHeaders = {
        server: lookup.headers.get("server"),
        contentType: lookup.headers.get("content-type"),
        wwwAuthenticate: lookup.headers.get("www-authenticate"),
        cfRay: lookup.headers.get("cf-ray"),
      };
    }
    return json(response);
  } catch {
    return json({ ok: false, lease: "invalid" }, 500);
  }
}

async function deleteMatchingDnsRecord(env, ip) {
  const headers = { Authorization: `Bearer ${env.CLOUDFLARE_DNS_TOKEN}` };
  const lookup = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records?type=A&name=${encodeURIComponent(env.CF_DNS_NAME)}`,
    { headers },
  );
  if (!lookup.ok) throw new Error(`DNS lookup returned ${lookup.status}`);
  const data = await lookup.json();
  const record = (data.result || []).find((item) => item.type === "A" && item.name === env.CF_DNS_NAME && item.content === ip);
  if (!record) return "DNS already absent or points at a newer VM";
  const removal = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records/${record.id}`,
    { method: "DELETE", headers },
  );
  if (!removal.ok) throw new Error(`DNS delete returned ${removal.status}`);
  return "matching DNS record deleted";
}

async function reap(env, force = false) {
  const raw = await env.EDGE_LEASES.get(LEASE_KEY);
  if (!raw) return { action: "none", reason: "no lease" };
  let lease;
  try {
    lease = JSON.parse(raw);
  } catch {
    await env.EDGE_LEASES.delete(LEASE_KEY);
    return { action: "none", reason: "invalid lease state discarded" };
  }
  const expiredFor = Date.now() - Date.parse(lease.expiresAt || "");
  if (!force && !lease.shutdownRequestedAt && (!Number.isFinite(expiredFor) || expiredFor < REAP_GRACE_MS)) {
    return { action: "none", reason: "lease active or still in grace period" };
  }

  // Read once before destroying. This prevents an invalid lease payload from
  // deleting an unrelated instance, even if the renewal credential is misused.
  const vultrHeaders = { Authorization: `Bearer ${env.VULTR_API_KEY}` };
  const lookup = await fetch(`https://api.vultr.com/v2/instances/${lease.instanceId}`, { headers: vultrHeaders });
  if (lookup.status === 404) {
    await env.EDGE_LEASES.delete(LEASE_KEY);
    return { action: "already-absent" };
  }
  if (!lookup.ok) throw new Error(`Vultr lookup returned ${lookup.status}`);
  const instance = (await lookup.json()).instance || {};
  if (!String(instance.label || "").startsWith("waw-edge-") || instance.main_ip !== lease.ip) {
    throw new Error("lease does not match the managed edge VM");
  }

  // Re-read just before deletion. A concurrent successful renewal wins.
  if ((await env.EDGE_LEASES.get(LEASE_KEY)) !== raw) return { action: "none", reason: "lease renewed concurrently" };
  const destroy = await fetch(`https://api.vultr.com/v2/instances/${lease.instanceId}`, {
    method: "DELETE",
    headers: vultrHeaders,
  });
  if (!destroy.ok && destroy.status !== 404) throw new Error(`Vultr delete returned ${destroy.status}`);

  let dns = "DNS cleanup deferred";
  try {
    dns = await deleteMatchingDnsRecord(env, lease.ip);
  } catch (error) {
    console.log(`VM deleted but DNS cleanup failed: ${error.message}`);
  }
  await env.EDGE_LEASES.delete(LEASE_KEY);
  return { action: "deleted", dns };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/renew") return renew(request, env);
    if (request.method === "POST" && url.pathname === "/shutdown") return requestShutdown(request, env, ctx);
    if (request.method === "GET" && url.pathname === "/health") return json({ ok: true });
    if (request.method === "GET" && url.pathname === "/status") return status(request, env);
    return json({ error: "not found" }, 404);
  },
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(reap(env)
      .then((result) => console.log(JSON.stringify(result)))
      .catch((error) => console.error(`scheduled reap failed: ${error.message}`)));
  },
};
