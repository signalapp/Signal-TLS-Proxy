#!/bin/bash

# Check for Docker Compose
if [ -x "$(command -v docker-compose)" ]; then
  DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version; then
  DOCKER_COMPOSE_CMD="docker compose"
else
  echo 'Error: neither docker-compose (v1) nor docker-compose-plugin (v2) is installed.' >&2
  exit 1
fi

# Paths for Certbot and IPSec
data_path="./data/certbot"
ipsec_conf_path="./data/ipsec"

# Get Domain Name
read -p "Enter domain name (eg. www.example.com): " domains

# Check for Existing Certificates
if [ -d "$data_path" ]; then
  read -p "Existing data found. Continue and replace existing certificate? (y/N) " decision
  if [ "$decision" != "Y" ] && [ "$decision" != "y" ]; then
    exit
  fi
fi

# TLS Parameters
if [ ! -e "$data_path/conf/options-ssl-nginx.conf" ] || [ ! -e "$data_path/conf/ssl-dhparams.pem" ]; then
  echo "### Downloading recommended TLS parameters ..."
  mkdir -p "$data_path/conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > "$data_path/conf/options-ssl-nginx.conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem > "$data_path/conf/ssl-dhparams.pem"
  echo
fi

# TLS Certificate Request
echo "### Requesting Let's Encrypt certificate for $domains ..."
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

echo "### TLS Certificates configured."

# IPSec Configuration
echo "### Configuring IPSec VPN ..."
mkdir -p "$ipsec_conf_path"
cat > "$ipsec_conf_path/ipsec.conf" <<EOF
config setup
    charondebug="ike 2, knl 2, cfg 2"
    uniqueids = no

conn %default
    keyexchange=ikev2
    ike=aes256-sha256-modp2048
    esp=aes256-sha256
    dpdaction=clear
    dpddelay=300s
    rekey=no

conn vpn-server
    left=%any
    leftsubnet=0.0.0.0/0
    leftcert=$domains
    right=%any
    rightdns=8.8.8.8,8.8.4.4
    rightsourceip=10.0.0.0/24
    authby=pubkey
    auto=start
EOF

cat > "$ipsec_conf_path/ipsec.secrets" <<EOF
: RSA "$domains.key"
EOF

# Docker Compose for StrongSwan (IPSec) and Nginx Proxy
cat > docker-compose.yml <<EOF
version: '3'
services:
  nginx:
    image: nginx:latest
    container_name: tls_proxy
    volumes:
      - ./data/certbot/conf:/etc/nginx/conf.d
      - ./data/certbot/active:/etc/letsencrypt
    ports:
      - "80:80"
      - "443:443"
    restart: always

  ipsec:
    image: hwdsl2/ipsec-vpn-server
    container_name: ipsec_vpn
    environment:
      - VPN_IPSEC_PSK=your_ipsec_psk
      - VPN_USER=your_vpn_user
      - VPN_PASSWORD=your_vpn_password
    volumes:
      - ./data/ipsec:/etc/ipsec.d
    ports:
      - "500:500/udp"
      - "4500:4500/udp"
    restart: always
EOF

echo
echo "### Starting services with Docker Compose ..."
${DOCKER_COMPOSE_CMD} up -d

# Status Check
echo "### IPSec VPN and TLS Proxy Setup Complete!"
echo "Access your proxy via: https://$domains"
echo "Connect to the IPSec VPN using the credentials:"
echo " - Pre-shared Key (PSK): your_ipsec_psk"
echo " - Username: your_vpn_user"
echo " - Password: your_vpn_password"
