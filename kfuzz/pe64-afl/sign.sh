#!/bin/bash

rm $2
winsign -d sha256 $1 $2 --certs ../cert/openssl.crt --key ../cert/openssl.key  -v

ls -la $2
