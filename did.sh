#! /usr/bin/bash

DID=${1:-did:example:123456789abcdefghi} # optional arg: DID to include
KEY=${2:-creds/did.pem}                  # optional arg: private key file to use
CERT=${3:-creds/did.crt}                 # optional arg: cert output file to use

CA=EJBCA
# CA=Insta # alternative
SUBJ="/CN=DID demo/OU=PPKI Playground/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE"


openssl ecparam -genkey -name prime256v1 -out "$KEY"
# openssl genrsa -out "$KEY" 2048 # alternative

. config/EJBCA.env 2>/dev/null # include decls needed for being able to use demo.cnf, ignoring errrors
DID="$DID" ./cmpClient -section $CA,did -subject "$SUBJ" -newkey "$KEY" -certout "$CERT" -verbosity 3 || exit 1

openssl x509 -noout -text -in "$CERT"
echo $SET_PROXY
