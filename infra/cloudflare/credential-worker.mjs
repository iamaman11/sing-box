const PROBE_SCHEMA_VERSION = 1;
const PROBE_GENERATION = 1;

function projectionValue(value) {
  if (value === "windows") return 1;
  if (value === "vm") return 2;
  return 0;
}

function encodeIsolationProbe(projection) {
  // CredentialIsolationProbe {
  //   schema_version: 1,
  //   generation: 1,
  //   projection: WINDOWS|VM,
  //   dummy_non_secret: true
  // }
  return Uint8Array.of(
    0x08, PROBE_SCHEMA_VERSION,
    0x10, PROBE_GENERATION,
    0x18, projection,
    0x20, 0x01,
  );
}

function requestIsExactProbe(request) {
  if (request.method !== "GET") return false;
  const url = new URL(request.url);
  if (url.pathname !== "/v1/credentials") return false;
  const keys = [...url.searchParams.keys()];
  return (
    keys.length === 1 &&
    keys[0] === "generation" &&
    url.searchParams.get("generation") === String(PROBE_GENERATION)
  );
}

export default {
  async fetch(request, env) {
    if (!requestIsExactProbe(request)) {
      return new Response("bounded credential probe only", {
        status: 404,
        headers: { "cache-control": "no-store" },
      });
    }

    const projection = projectionValue(env.EDGE_PROJECTION);
    if (projection === 0) {
      return new Response("credential projection is not configured", {
        status: 503,
        headers: { "cache-control": "no-store" },
      });
    }

    return new Response(encodeIsolationProbe(projection), {
      status: 200,
      headers: {
        "cache-control": "no-store",
        "content-type": "application/x-protobuf",
      },
    });
  },
};
