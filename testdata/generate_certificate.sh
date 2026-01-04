#!/bin/bash

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test.key

openssl req -x509 -new -key test.key -subj "/C=RS/O=Test/OU=Parser/CN=Test Cert" -days 365 -out test.pem

openssl x509 -in test.pem -out test.der -outform DER

openssl x509 -in test.der -inform DER -noout -modulus >> test.modulus