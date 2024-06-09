---
title: "crAPI and VAPI Installation"
date: 2023-04-03T16:13:35+03:00
menu:
  sidebar:
    name: crAPI & VAPI setup
    identifier: crAPI-and-VAPI-installation
    parent: apisecurity
    weight: 10
    
draft: true
---
To be able to run crAPI and VAPI locally, we are going to install the following first
1. Docker
2. Golang-go

## For linux user
- Docker
install docker by running the command`sudo apt-get install docker.io docker-compose`
- Golang-go
Install golang-go by running the command `sudo apt install golang-go`

 #### crAP Installation
 ```bash
 sudo curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml

sudo docker-compose pull

sudo docker-compose -f docker-compose.yml --compatibility up -d`
```





