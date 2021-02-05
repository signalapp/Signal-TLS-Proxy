#!/bin/bash

if ! [ -x "$(command -v docker-compose)" ]; then
  echo 'Error: docker-compose is not installed.' >&2
  exit 1
fi

data_path="./data/certbot"
domains="$SP_CERTBOT_DOMAIN"

# Only ask for domain if it's not set by environment
if [ -z "$domains" ]; then
  read -p "Enter domain name (eg. www.example.com): " domains
fi

decision="$SP_REPLACE_EXISTING"
if [ -L "$data_path/conf/active" ]; then
  if [ -z "$decision" ]; then
    read -p "Existing data found. Continue and replace existing certificate? (y/N) " decision
  fi

  if [ "$decision" != "Y" ] && [ "$decision" != "y" ]; then
    exit
  fi
fi


if [ ! -e "$data_path/conf/options-ssl-nginx.conf" ] || [ ! -e "$data_path/conf/ssl-dhparams.pem" ]; then
  echo "### Downloading recommended TLS parameters ..."
  mkdir -p "$data_path/conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > "$data_path/conf/options-ssl-nginx.conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem > "$data_path/conf/ssl-dhparams.pem"
  echo
fi

echo "### Requesting Let's Encrypt certificate for $domains ..."
#Join $domains to -d args
domain_args=""
for domain in "${domains[@]}"; do
  domain_args="$domain_args -d $domain"
done

docker-compose run -p 80:80 --rm --entrypoint "\
  sh -c \"certbot certonly --standalone \
    --register-unsafely-without-email \
    $domain_args \
    --agree-tos \
    --force-renewal && \
    ln -fs /etc/letsencrypt/live/$domains/ /etc/letsencrypt/active\"" certbot
echo
echo "After running 'docker-compose up --detach' you can share your proxy as: https://signal.tube/#$domains"
