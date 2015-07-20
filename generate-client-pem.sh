#!/bin/bash

NAME="anonymous+28375@headfirstselect.nl"

openssl pkcs12 -export -clcerts -in certs/$NAME.crt -inkey $NAME.key -out client.p12
