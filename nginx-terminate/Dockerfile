FROM alpine:3.17 as build

ARG NGINX_VER='1.22.1'

RUN apk add --no-cache \
      build-base \
      libressl-dev \
      pcre-dev \
      zlib-dev

WORKDIR /opt

RUN wget "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" \
    && tar -zxvf "nginx-${NGINX_VER}.tar.gz" \
    && cd "nginx-${NGINX_VER}" \
    && ./configure \
        --prefix=/opt/nginx \
        --user=nginx \
        --group=nginx \
        --with-http_ssl_module \
        --with-ipv6 \
        --with-threads \
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
    && make && make install \
    && cd .. && rm -rf "nginx-${NGINX_VER}*"

FROM alpine:3.17 as final

RUN apk upgrade --update-cache \
    && apk add \
      libressl3.6-libcrypto \
      libressl3.6-libssl \
      pcre \
    && rm -rf /var/cache/apk

COPY --from=build /opt/ /opt/

RUN addgroup -S nginx \
    && adduser -SDHG nginx nginx

EXPOSE 443

CMD ["/opt/nginx/sbin/nginx", "-c", "/etc/nginx/conf.d/nginx.conf", "-g", "daemon off;"]
