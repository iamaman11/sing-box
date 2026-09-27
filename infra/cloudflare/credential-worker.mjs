const PROBE_GENERATION = "1";
const PROBE_HEX = "__PROBE_HEX__";

function decodeHex(value) {
  if (value.length === 0 || value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) {
    throw new Error("invalid embedded credential probe");
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function requestIsExactProbe(request) {
  if (request.method !== "GET") return false;
  const url = new URL(request.url);
  if (url.pathname !== "/v1/credentials") return false;
  const keys = [...url.searchParams.keys()];
  return (
    keys.length === 1 &&
    keys[0] === "generation" &&
    url.searchParams.get("generation") === PROBE_GENERATION
  );
}

const PROBE_BYTES = decodeHex(PROBE_HEX);

export default {
  async fetch(request) {
    if (!requestIsExactProbe(request)) {
      return new Response("bounded credential probe only", {
        status: 404,
        headers: { "cache-control": "no-store" },
      });
    }

    return new Response(PROBE_BYTES, {
      status: 200,
      headers: {
        "cache-control": "no-store",
        "content-type": "application/x-protobuf",
      },
    });
  },
};
