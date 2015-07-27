#!/bin/bash

NAME="demo"

openssl pkcs12 -export -clcerts -in certs/$NAME.crt -inkey $NAME.key -out $NAME-client.p12
