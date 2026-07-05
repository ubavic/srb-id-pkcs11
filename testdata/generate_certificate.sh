#!/bin/bash

format_hex() {
    local in="$1"
    local extension="$2"

    tr '[:upper:]' '[:lower:]' < "$in.tmp" \
        | cut -d= -f2 \
        | fold -w 16 \
        | sed 's/../0x&, /g' \
        > "$in.$extension"
}

sizes=(1024 2048)

for size in "${sizes[@]}"; do
    openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:$size -out "$size.key"
    openssl req -x509 -new -key "$size.key" -subj "/C=RS/O=Test/OU=Parser/CN=Test Cert" -days 365 -out "$size.pem"
    openssl x509 -in "$size.pem" -out "$size.der" -outform DER
    openssl x509 -in "$size.der" -inform DER -noout -modulus > "$size.tmp"
    format_hex "$size" "modulus"
    openssl x509 -in "$size.der" -inform DER -noout -serial  > "$size.tmp"
    format_hex "$size" "serial"
    rm -f "$size.tmp"
done
