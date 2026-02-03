#! /bin/bash
set -e
#set -x  #for debug

# This script generates the certificates needed for the CMP server and the signer

mkcert_sh="../../../certs/mkcert.sh"

# Specify whether PQC or Classic algorithms are used
# Possible values: "PQC" or "Classic"
# Check if Algo_used is defined from environment variable, if not assign it "Classic"
if [[ -z "${Algo_used}" ]]; then
    Algo_used="Classic"
fi

if [ -z "$DAYS" ]; then  
    DAYS=36524 # 100 years, with 24 leap years per 100 years until 2400  
fi

if [[ ${Algo_used} == "PQC" ]]; then
    # sever certificate algorithms
    server_rootca_keyalg="SLH-DSA-SHAKE-192s"
    server_leaf_keyalg="MLDSA65"
    # rootCACert update test case
    new_rootca_keyalg="MLDSA65"

    # End-entity certificate algorithms
    signer_rootca_keyalg="MLDSA65"
    signer_interca_keyalg="MLDSA65"
    signer_subinterca_keyalg="MLDSA65"
    signer_leaf_keyalg="SLH-DSA-SHAKE-192s"
else
    # sever certificate algorithms
    server_rootca_keyalg="rsa"
    server_leaf_keyalg="rsa"
    # rootCACert update test case
    new_rootca_keyalg="rsa"

    # End-entity certificate algorithms
    signer_rootca_keyalg="rsa"
    signer_interca_keyalg="rsa"
    signer_subinterca_keyalg="rsa"
    signer_leaf_keyalg="rsa"
fi


# CMP server certificate
rename_serverfiles() {
    echo "Renaming server files"
    # removing unneeded files
    rm server_root-key.pem server_root-pubkey.pem newWithNew-key.pem newWithNew-pubkey.pem
    mv server_root-cert.pem server_root.crt
    cp server_root.crt trusted.crt
    if [[ -f big_trusted.crt ]]; then
        cat trusted.crt >> big_trusted.crt
    fi
    cp server_root.crt oldWithOld.pem
    mv server-key.pem server.key
    mv server-cert.pem server.crt
    mv newWithNew-cert.pem newWithNew.pem
}

remove_serverfiles() {
    echo "Removing server files"
    rm -f server_root.crt trusted.crt server.key server-crt
    rm -f oldWithOld.pem newWithNew.pem oldWithNew.pem newWithOld.pem
}

gen_server_chain() {
    remove_serverfiles
    # allow time to sync file system after deletions
    sleep 5
    OPENSSL_KEYALG=${server_rootca_keyalg} \
    $mkcert_sh genroot "Root CA" server_root-key server_root-cert
    OPENSSL_KEYALG=${server_leaf_keyalg} \
    $mkcert_sh genee -p serverAuth,cmKGA server.example server-key server-cert server_root-key server_root-cert

    OPENSSL_KEYALG=${new_rootca_keyalg} \
    $mkcert_sh genroot "Root CA" newWithNew-key newWithNew-cert

    openssl pkey -in newWithNew-key.pem -out newWithNew-pubkey.pem -outform PEM -pubout
    openssl x509 -new -subj "/CN=Root CA" -CA server_root-cert.pem -CAkey server_root-key.pem \
        -out newWithOld.pem -force_pubkey newWithNew-pubkey.pem \
        -extfile <(printf "basicConstraints=critical,CA:true")

    openssl pkey -in server_root-key.pem -out server_root-pubkey.pem -outform PEM -pubout
    openssl x509 -new -subj "/CN=Root CA" -CA newWithNew-cert.pem -CAkey newWithNew-key.pem \
        -out oldWithNew.pem -force_pubkey server_root-pubkey.pem \
        -extfile <(printf "basicConstraints=critical,CA:true")

    rename_serverfiles
}

gen_demoCAfolder() {
    echo "Generating demoCA folder"
    mkdir -p demoCA
    touch demoCA/index.txt
    echo 1007 > demoCA/crlnumber
}
rename_signerfiles() {
    echo "Renaming signer files"
    mv signer_root-cert.pem root.crt
    if [[ -f big_root.crt ]]; then
        cat root.crt >> big_root.crt
    fi
    cp root.crt signer_root.crt
    rm -f signer_root-key.pem signer_interCA-key.pem signer_interCA-cert.pem \
        signer_subinterCA-key.pem
    mv signer_subinterCA-cert.pem issuing.crt
    mv signer_subinterCA-crl.pem newcrl.pem
    mv signer_leaf-key.pem new.key
    openssl pkey -in new.key -out new_pass_12345.key -aes256 -passout file:12345.txt

    cp new.key signer.key
    mv signer_leaf-cert.pem signer_only.crt
    mv signer_issuing-cert.pem signer_issuing.crt
    mv signer_chain.pem signer.crt
}
remove_signerfiles() {
    echo "Removing signer files"
    rm -f root.crt signer_root.crt newcrl.pem new.key signer.key signer_only.crt \
        signer_issuing.crt signer.crt issuing.crt
}

#  cannot use genee() because this uses a self-signature for the POP in a PKCS#10 CSR
genee_kem() {
    local cn=$1; shift
    local key=$1; shift
    local cert=$1; shift
    local cakey=$1; shift
    local ca=$1; shift
    echo "Generating KEM certificate"
    openssl genpkey -algorithm "$OPENSSL_KEYALG" -out ${key}.pem -outpubkey ${cn}-pubkey.pem
    openssl x509 -new -subj "/CN=${cn}" -CA ${ca}.pem -CAkey ${cakey}.pem \
        -out ${cert}.pem -force_pubkey ${cn}-pubkey.pem \
        -extfile <(printf "basicConstraints=critical,CA:false\nkeyUsage=critical,keyEncipherment")
    rm -f ${cn}-pubkey.pem
}

gen_client_chain() {
    echo "Generating signer certificates"
    remove_signerfiles
    # allow time to sync file system after deletions
    sleep 5
    OPENSSL_KEYALG=${signer_rootca_keyalg} \
    $mkcert_sh genroot "signer-rootCA" signer_root-key signer_root-cert
    OPENSSL_KEYALG=${signer_interca_keyalg} \
    $mkcert_sh genca "signer-interCA" signer_interCA-key signer_interCA-cert signer_root-key signer_root-cert
    OPENSSL_KEYALG=${signer_subinterca_keyalg} \
    $mkcert_sh genca "signer-subinterCA" signer_subinterCA-key signer_subinterCA-cert signer_interCA-key signer_interCA-cert

    OPENSSL_KEYALG=${signer_leaf_keyalg}
    if [[ "$signer_leaf_keyalg" == *"KEM"* ]]; then
        OPENSSL_KEYALG=${signer_leaf_keyalg} genee_kem "signer-leaf" signer_leaf-key signer_leaf-cert signer_subinterCA-key signer_subinterCA-cert
    else
        OPENSSL_KEYALG=${signer_leaf_keyalg} \
        $mkcert_sh genee -p clientAuth "signer-leaf" signer_leaf-key signer_leaf-cert signer_subinterCA-key signer_subinterCA-cert
    fi

    gen_demoCAfolder
    openssl ca -gencrl -keyfile signer_subinterCA-key.pem -cert signer_subinterCA-cert.pem -out signer_subinterCA-crl.pem -crldays $DAYS \
            -config <(printf "[ca]\ndefault_ca= CA_default\n[CA_default]\n%s\n%s\n%s\n" \
		      "database = ./demoCA/index.txt" "crlnumber = ./demoCA/crlnumber" "default_md = default")
    cat signer_leaf-cert.pem signer_subinterCA-cert.pem signer_interCA-cert.pem > signer_chain.pem
    cat signer_subinterCA-cert.pem signer_interCA-cert.pem signer_root-cert.pem > signer_fullchain.pem
    openssl pkcs12 -export -out signer.p12 -inkey signer_leaf-key.pem -in signer_leaf-cert.pem -certfile signer_fullchain.pem -password file:12345.txt
    rm -f signer_fullchain.pem
    cat signer_subinterCA-cert.pem signer_interCA-cert.pem > signer_issuing-cert.pem
    rename_signerfiles
}



all() {
    gen_server_chain
    gen_client_chain
}

"$@"
