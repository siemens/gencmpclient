#! /usr/bin/bash

DID=${1:-did:example:123456789abcdefghi}
KEY=${2:-creds/did.pem}
CERT=${3:-creds/did.crt}

CA=EJBCA
# CA=Insta # alternative
SUBJ="/CN=DID demo/OU=PPKI Playground/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE"

openssl ecparam -genkey -name prime256v1 -out "$KEY"
# openssl genrsa -out "$KEY" 2048 # alternative

DID="$DID" ./cmpClient -section $CA,did -subject "$SUBJ" -newkey "$KEY" -certout "$CERT" -verbosity 3 || exit 1

openssl x509 -noout -text -in "$CERT"
