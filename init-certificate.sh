#!/bin/bash

if [ -x "$(command -v docker-compose)" ]; then
  DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version; then
  DOCKER_COMPOSE_CMD="docker compose"
else
  echo 'Error: neither docker-compose (v1) nor docker-compose-plugin (v2) is installed.' >&2
  exit 1
fi

data_path="./data/certbot"

read -p "Enter domain name (eg. www.example.com): " domains

if [[ -d "$data_path" ]]; then
    read -r -p "Existing data found. Continue and replace existing certificate? (y/N) " decision
    [[ "$decision" == [Yy] ]] || exit 1
fi

if [ ! -e "$data_path/conf/options-ssl-nginx.conf" ] || [ ! -e "$data_path/conf/ssl-dhparams.pem" ]; then
  echo "### Downloading recommended TLS parameters ..."
  mkdir -p "$data_path/conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/refs/heads/main/certbot/src/certbot/_internal/plugins/nginx/tls_configs/options-ssl-nginx.conf > "$data_path/conf/options-ssl-nginx.conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/main/certbot/src/certbot/ssl-dhparams.pem > "$data_path/conf/ssl-dhparams.pem"
  echo
fi

echo "### Requesting Let's Encrypt certificate for $domains ..."
#Join $domains to -d args
domain_args=""
for domain in "${domains[@]}"; do
  domain_args="$domain_args -d $domain"
done

${DOCKER_COMPOSE_CMD} run -p 80:80 --rm --entrypoint "\
  sh -c \"certbot certonly --standalone \
    --register-unsafely-without-email \
    $domain_args \
    --agree-tos \
    --force-renewal && \
    ln -fs /etc/letsencrypt/live/$domains/ /etc/letsencrypt/active\"" certbot
echo
echo "After running '${DOCKER_COMPOSE_CMD} up --detach' you can share your proxy as: https://signal.tube/#$domains"
