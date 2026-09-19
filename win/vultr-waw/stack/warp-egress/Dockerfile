ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG WARP_VERSION
ARG WARP_URL
ARG WARP_SHA256

ENV DEBIAN_FRONTEND=noninteractive

RUN test -n "$WARP_VERSION" &&     test -n "$WARP_URL" &&     test -n "$WARP_SHA256"

RUN apt-get update && apt-get install -y     ca-certificates     curl     iproute2     iptables     procps     dbus     socat     && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "$WARP_URL" -o /tmp/cloudflare-warp.deb && \
    echo "$WARP_SHA256  /tmp/cloudflare-warp.deb" | sha256sum -c - && \
    test "$(dpkg-deb -f /tmp/cloudflare-warp.deb Package)" = "cloudflare-warp" && \
    test "$(dpkg-deb -f /tmp/cloudflare-warp.deb Architecture)" = "amd64" && \
    test "$(dpkg-deb -f /tmp/cloudflare-warp.deb Version)" = "$WARP_VERSION" && \
    apt-get update && \
    apt-get install -y /tmp/cloudflare-warp.deb && \
    test "$(dpkg-query -W -f='${Version}' cloudflare-warp)" = "$WARP_VERSION" && \
    rm -f /tmp/cloudflare-warp.deb && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
