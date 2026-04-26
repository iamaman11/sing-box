FROM debian:bookworm-slim

ARG SING_BOX_VERSION=1.13.8
ARG SING_BOX_URL=https://github.com/SagerNet/sing-box/releases/download/v1.13.8/sing-box-1.13.8-linux-amd64-glibc.tar.gz
ARG SING_BOX_SHA256=766abdefb4c0e62fbfed6fe2d2502731afb8fa578fae6219bd62982a66741341

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    tar \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "$SING_BOX_URL" -o /tmp/sing-box.tar.gz && \
    echo "$SING_BOX_SHA256  /tmp/sing-box.tar.gz" | sha256sum -c - && \
    mkdir -p /tmp/sing-box && \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp/sing-box && \
    cp /tmp/sing-box/sing-box-*/sing-box /usr/local/bin/sing-box && \
    chmod +x /usr/local/bin/sing-box && \
    rm -rf /tmp/sing-box /tmp/sing-box.tar.gz

ENTRYPOINT ["/usr/local/bin/sing-box"]
