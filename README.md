# Signal TLS Proxy

To run a Signal TLS proxy, you will need a host that has ports 80 and 443 available and a domain name that points to that host.

1. Install docker and docker-compose (https://docs.docker.com/engine/install/)
1. Ensure your current user has access to docker (`adduser $USER docker`)
1. Clone this repository
2. `cd ./Signal-TLS-Proxy`
1. `docker compose build`
1. `docker volume create --name=caddy_data`
1. `sed -i 's/sub.example.com/sub.my-domain.com/g' config/caddy.json`
1. `docker compose up --detach`

Additionally, if you'd like to harden your server against memory corruption vulnerabilities, run the following commands. This will install [hardened_malloc](https://github.com/GrapheneOS/hardened_malloc) on your server and add it to your path automatically.

1. `chmod +x ./harden.sh`
2. `./harden.sh`

Your proxy is now running! You can share this with the URL `https://signal.tube/#<your_host_name>`

## Updating from a previous version

If you've previously run a proxy, please update to the most recent version by pulling the most recent changes from `main`, then restarting your Docker containers:

```shell
git pull
docker compose down
docker compose up --detach
```
