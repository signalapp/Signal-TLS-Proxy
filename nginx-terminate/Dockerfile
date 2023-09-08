FROM ubuntu:22.04

RUN apt-get update && apt-get -y upgrade && \
    apt-get install -y wget libpcre3-dev build-essential libssl-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN wget https://nginx.org/download/nginx-1.25.2.tar.gz && \
    tar -zxvf nginx-1.*.tar.gz && \
    cd nginx-1.* && \
    ./configure --prefix=/opt/nginx --user=nginx --group=nginx --with-http_ssl_module --with-ipv6 --with-threads --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module && \
    make && make install && \
    cd .. && rm -rf nginx-1.*

RUN adduser --system --no-create-home --disabled-login --disabled-password --group nginx

WORKDIR /

EXPOSE 443

CMD ["/opt/nginx/sbin/nginx", "-c", "/etc/nginx/conf.d/nginx.conf", "-g", "daemon off;"]
