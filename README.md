# Signal TLS Proxy

## Requirements

To run a Signal TLS proxy, you will need 

- a host that has ports 80 and 443 available (an inexpensive and tiny VPS can easily handle hundreds of concurrent users)
- a domain name

## Installation

Use SSH to connect to your host, then run these commands:

```bash
sudo apt update
sudo apt --yes install docker docker-compose git
git clone https://github.com/signalapp/Signal-TLS-Proxy.git
cd Signal-TLS-Proxy
sudo ./init-certificate.sh # You will be prompted to enter the domain or subdomain that is pointing to this server’s IP address.
sudo docker-compose up --detach
```

Your proxy is now running! You can share this with the URL `https://signal.tube/#<your_host_name>` 
