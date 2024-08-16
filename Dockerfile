FROM caddy:builder AS builder

RUN xcaddy build \
    --with github.com/mholt/caddy-l4

FROM cgr.dev/chainguard/caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy