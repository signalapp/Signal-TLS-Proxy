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

## Having trouble with command lines or not familiar with them?

If you are hosting a personal website, you can run a Signal proxy too. It's basically just creating an empty folder and uploading these files to it.

1. Log into your hosting provider console
2. Go to your domain management options
3. Create a subdomain: 
  - Type : A record
  - Name :[a-random-word]
  - Value: [your server's IP]
  You know have a subdomain [a-random-word].yourdomain. You should also have a new empty directory (also called "root") on your server, named after your subdomain.
4. Download this repository (and unzip it) or type `git clone git@github.com:signalapp/Signal-TLS-Proxy.git` in your terminal
  The goal is to put the files you just downloaded in your subdomain directory
5. From your hosting provider console, find your file manager (If you are already used to FTP, that will do the job). If not, th'at's totally fine, your hosting provider probably has a set up to let you access your website's files.
6. Find your newly created empty directory and import the files. 

That's it, you are running a Signal proxy ! Thank you for your service !
