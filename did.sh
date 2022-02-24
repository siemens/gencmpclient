#! /usr/bin/bash

DID=${1:-did:example:123456789abcdefghi} # optional arg: DID to include
KEY=${2:-creds/did.pem}                  # optional arg: private key file to use
CERT=${3:-creds/did.crt}                 # optional arg: cert output file to use

CA=EJBCA
# CA=Insta # alternative
SUBJ="/CN=DID demo/OU=PPKI Playground/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE"

# decls needed for being able to use demo.cnf:
export  EJBCA_HOST="ppki-playground.ct.siemens.com" \
	EJBCA_OCSP_URL="http://ppki-playground.ct.siemens.com/ejbca/publicweb/status/ocsp" \
	EJBCA_CDP_URL_PREFIX="http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=DER&issuer=CN=PPKI+Playground+" \
	EJBCA_CDPS="Infrastructure+Root+CA+v1.0 Infrastructure+Issuing+CA+v1.0 ECC+Root+CA+v1.0 RSA+Root+CA+v1.0" \
	EJBCA_CDP_URL_POSTFIX="%2cOU=Corporate+Technology%2cOU=For+internal+test+purposes+only%2cO=Siemens%2cC=DE" \
	EJBCA_CMP_ISSUER="creds/PPKI_Playground_ECCIssuingCAv10.crt" \
	EJBCA_CMP_CLIENT="creds/PPKI_Playground_CMP.p12" \
	EJBCA_TLS_CLIENT="creds/PPKI_Playground_TLS.p12" \
	EJBCA_CMP_TRUSTED="creds/PPKI_Playground_ECCRootCAv10.crt" \
	EJBCA_TRUSTED="creds/PPKI_Playground_InfrastructureRootCAv10.crt" \
	EJBCA_UNTRUSTED="creds/PPKI_Playground_InfrastructureIssuingCAv10.crt" \
	EJBCA_CMP_RECIPIENT="/CN=PPKI Playground ECC Issuing CA v1.0/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE" \
	EJBCA_CMP_SERVER="/CN=Product PKI Playground CMP Signer/OU=PPKI Playground/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE" \
	EJBCA_CMP_SUBJECT="/CN=test-genCMPClientDemo/OU=PPKI Playground/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE" \
	EJBCA_CMP_SUBJECT_ECC="/CN=ECC-EE/OU=PPKI Playground/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE" \
	EJBCA_ENABLED=1


openssl ecparam -genkey -name prime256v1 -out "$KEY"
# openssl genrsa -out "$KEY" 2048 # alternative

DID="$DID" ./cmpClient -section $CA,did -subject "$SUBJ" -newkey "$KEY" -certout "$CERT" -verbosity 3 || exit 1

openssl x509 -noout -text -in "$CERT"
