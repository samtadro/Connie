#!/bin/bash


echo startsing command 
openssl version
var=$(hostname -f) 
openssl req -x509 -newkey rsa:4096 -keyout /opt/Connie/conf/certs/key.pem -out /opt/Connie/conf/certs/cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=CA/L=LA/O=Connie/OU=indevUnite/CN=$var/"

