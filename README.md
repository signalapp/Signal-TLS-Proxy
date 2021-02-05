# Signal TLS Proxy

To run a Signal TLS proxy, you will need a host with a domain name that has ports 80 and 443 available.

1. Install docker and docker-compose (`apt update && apt install docker.io docker-compose`)
1. Clone this repository
1. `./init-certificate.sh`
1. `docker-compose up --detach`

Your proxy is now running! You can share this with the URL `https://signal.tube/#<your_host_name>` 
