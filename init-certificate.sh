
#!/usr/bin/env bash

# Prefer Docker Compose v2, fall back to v1.
if docker compose version &>/dev/null; then
  compose=(docker compose)
elif docker-compose version &>/dev/null; then
  compose=(docker-compose)
else
  echo 'Error: Docker Compose v1 or v2 is required.' >&2
  exit 1
fi

# Always run from the project root.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$script_dir" || exit 1
data_path='./data/certbot'

read -r -p 'Enter domain name(s), separated by spaces: ' -a domains
if ((${#domains[@]} == 0)); then
  echo 'Error: at least one domain is required.' >&2
  exit 1
fi

if [[ -d "$data_path" ]]; then
  read -r -p 'Existing data found. Continue and replace existing certificate? (y/N) ' decision
  [[ "$decision" == [Yy] ]] || exit 1
fi

# Download missing files without leaving partial downloads.
download_if_missing() {
  local url=$1 dest=$2 temp
  [[ -f "$dest" ]] && return 0

  printf '### Downloading %s ...\n' "${dest##*/}"
  temp=$(mktemp "$dest.XXXXXX") || return 1

  if curl -fsSL "$url" -o "$temp" && mv "$temp" "$dest"; then
    return 0
  fi

  rm -f "$temp"
  return 1
}

conf_dir="$data_path/conf"
base_url='https://raw.githubusercontent.com/certbot/certbot/main/certbot/src/certbot'
mkdir -p "$conf_dir" || exit 1

download_if_missing "$base_url/_internal/plugins/nginx/tls_configs/options-ssl-nginx.conf" "$conf_dir/options-ssl-nginx.conf" || exit 1
download_if_missing "$base_url/ssl-dhparams.pem" "$conf_dir/ssl-dhparams.pem" || exit 1

# Build arguments for each domain.
domain_args=()
for domain in "${domains[@]}"; do
  domain_args+=(-d "$domain")
done

printf "### Requesting Let's Encrypt certificate for %s ...\n" "${domains[*]}"

if ! "${compose[@]}" run -p 80:80 --rm --entrypoint sh certbot \
  -c 'primary_domain=$1; shift
      certbot certonly --standalone \
        --register-unsafely-without-email \
        --agree-tos --force-renewal "$@" &&
      ln -sfn "/etc/letsencrypt/live/$primary_domain/" /etc/letsencrypt/active' \
  sh "${domains[0]}" "${domain_args[@]}"; then
  echo 'Error: certificate request or symlink update failed.' >&2
  exit 1
fi

printf "\nAfter running '%s up --detach' you can share your proxy as: https://signal.tube/#%s\n" "${compose[*]}" "${domains[0]}"
printf "### Certificate for %s has been successfully obtained and linked.\n" "${domains[0]}"