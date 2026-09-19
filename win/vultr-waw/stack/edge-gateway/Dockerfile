ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG SING_BOX_VERSION
ARG SING_BOX_URL
ARG SING_BOX_SHA256

RUN test -n "$SING_BOX_VERSION" &&     test -n "$SING_BOX_URL" &&     test -n "$SING_BOX_SHA256"

RUN apt-get update && apt-get install -y     ca-certificates     curl     tar     && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "$SING_BOX_URL" -o /tmp/sing-box.tar.gz &&     echo "$SING_BOX_SHA256  /tmp/sing-box.tar.gz" | sha256sum -c - &&     mkdir -p /tmp/sing-box &&     tar -xzf /tmp/sing-box.tar.gz -C /tmp/sing-box &&     cp /tmp/sing-box/sing-box-*/sing-box /usr/local/bin/sing-box &&     chmod +x /usr/local/bin/sing-box &&     test "$(/usr/local/bin/sing-box version | head -n 1)" = "sing-box version $SING_BOX_VERSION" &&     rm -rf /tmp/sing-box /tmp/sing-box.tar.gz

ENTRYPOINT ["/usr/local/bin/sing-box"]
