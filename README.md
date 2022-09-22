# Signal TLS Proxy

To run a Signal TLS proxy, you will need a host that has ports 80 and 443 available and a domain name that points to that host.

1. Install docker and docker-compose (`apt update && apt install docker docker-compose`)
1. Ensure your current user has access to docker (`adduser $USER docker`)
1. Clone this repository
1. `./init-certificate.sh`
1. `docker-compose up --detach`

Your proxy is now running! You can share this with the URL `https://signal.tube/#<your_host_name>`

## Updating from a previous version

If you've previously run a proxy, please update to the most recent version by pulling the most recent changes from `main`, then restarting your Docker containers:

```shell
git pull
docker-compose down
docker-compose up --detach
```
