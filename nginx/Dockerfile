FROM ubuntu:20.04

RUN apt-get update && apt-get -y upgrade && \
    apt-get install -y wget libpcre3-dev build-essential libssl-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN VERSION="1.18.0" && \
    # https://nginx.org/en/pgp_keys.html
    NGINX_GPGKEY=520A9993A1C052F8; \
    found=''; \
    for server in \
        ha.pool.sks-keyservers.net \
        hkp://keyserver.ubuntu.com:80 \
        hkp://p80.pool.sks-keyservers.net:80 \
        pgp.mit.edu \
    ; do \
        echo "Fetching GPG key $NGINX_GPGKEY from $server"; \
        gpg --keyserver "$server" --recv-keys "$NGINX_GPGKEY" && found=yes && break; \
    done; \
    test -z "$found" && echo >&2 "error: failed to fetch GPG key $NGINX_GPGKEY" && exit 1; \
    wget https://nginx.org/download/nginx-${VERSION}.tar.gz.asc https://nginx.org/download/nginx-${VERSION}.tar.gz && \
    gpg --verify nginx-${VERSION}.tar.gz.asc nginx-${VERSION}.tar.gz && \
    tar -zxvf nginx-${VERSION}.tar.gz && \
    cd nginx-${VERSION} && \
    ./configure --prefix=/opt/nginx --user=nginx --group=nginx --with-http_ssl_module --with-ipv6 --with-threads --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module && \
    make && make install && \
    cd .. && rm -rf nginx-${VERSION}*

RUN adduser --system --no-create-home --disabled-login --disabled-password --group nginx

WORKDIR /

EXPOSE 443

CMD ["/opt/nginx/sbin/nginx", "-c", "/etc/nginx/conf.d/nginx.conf", "-g", "daemon off;"]
