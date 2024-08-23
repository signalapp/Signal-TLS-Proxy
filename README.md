# Signal TLS Proxy

To run a Signal TLS proxy, you will need a host that has ports 80 and 443 available and a domain name that points to that host.

1. Install Docker by following the instructions at https://docs.docker.com/engine/install/
2. Clone this repository
3. `./init-certificate.sh`
4. `docker compose up --detach`

Your proxy is now running! You can share this with the URL `https://signal.tube/#<your_host_name>`

## Updating from a previous version

If you've previously run a proxy, please update to the most recent version by pulling the most recent changes from `main`, then restarting your Docker containers:

```shell
git pull
docker compose down
docker compose build
docker compose up --detach
```

## Contributions welcome

We want this proxy to be simple to deploy for a broad population, but we know that it won’t fit all deployments—especially  advanced users that already have running servers or specific technology preferences. We welcome contributions that make incremental improvements, updates, and improve compatibility, but aren’t considering significant architectural changes.
