#! /bin/bash
set -e
#set -x  #for debug

# This script generates the certificates needed for the CMP server and the signer

if [[ ! -f $mkcert_sh ]]; then
    mkcert_sh="../../../certs/mkcert.sh"
fi

# sever certificate algorithms
if [ -z "$server_rootca_keyalg" ]; then
    server_rootca_keyalg="MLDSA65"
fi
if [ -z "$server_leaf_keyalg" ]; then
    server_leaf_keyalg="SLH-DSA-SHAKE-192s"
fi
# rootCACert update test case
if [ -z "$new_rootca_keyalg" ]; then
    new_rootca_keyalg="SLH-DSA-SHAKE-192s"
fi

# End-entity certificate algorithms
if [ -z "$signer_rootca_keyalg" ]; then
    signer_rootca_keyalg="MLDSA65"
fi
if [ -z "$signer_interca_keyalg" ]; then
    signer_interca_keyalg="MLDSA65"
fi
if [ -z "$signer_subinterca_keyalg" ]; then
    signer_subinterca_keyalg="MLDSA65"
fi
if [ -z "$signer_leaf_keyalg" ]; then
    signer_leaf_keyalg="SLH-DSA-SHAKE-192s"
fi

# CMP server certificate
rename_serverfiles() {
    echo "Renaming server files"
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
    rm -f server.key server-crt trusted.crt server_root.crt
    rm -f oldWithOld.pem newWithNew.pem oldWithNew.pem newWithOld.pem
}

gen_servercert() {
    remove_serverfiles
    sleep 5
    OPENSSL_KEYALG=${server_rootca_keyalg} \
    $mkcert_sh genroot "Root CA" server_root-key server_root-cert
    OPENSSL_KEYALG=${server_leaf_keyalg} \
    $mkcert_sh genee -p serverAuth,cmKGA server.example server-key server-cert server_root-key server_root-cert

    OPENSSL_KEYALG=${new_rootca_keyalg} \
    $mkcert_sh genroot "Root CA" newWithNew-key newWithNew-cert

    openssl pkey -in newWithNew-key.pem -out newWithNew-pubkey.pem -outform PEM -pubout
    openssl x509 -new -subj "/CN=Root CA" -CA server_root-cert.pem -CAkey server_root-key.pem \
        -out newWithOld.pem -force_pubkey newWithNew-pubkey.pem -extensions SAN \
        -extfile <(printf "[SAN]\nbasicConstraints=critical,CA:true")

    openssl pkey -in server_root-key.pem -out server_root-pubkey.pem -outform PEM -pubout
    openssl x509 -new -subj "/CN=Root CA" -CA newWithNew-cert.pem -CAkey newWithNew-key.pem \
        -out oldWithNew.pem -force_pubkey server_root-pubkey.pem -extensions SAN \
        -extfile <(printf "[SAN]\nbasicConstraints=critical,CA:true")

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
    openssl pkey -in new.key -out new_pass_12345.key -aes256 -passout pass:12345
    echo "12345" > 12345.txt
    cp new.key signer.key
    mv signer_leaf-cert.pem signer_only.crt
    mv signer_issuing-cert.pem signer_issuing.crt
    mv signer_chain.pem signer.crt
}
remove_signerfiles() {
    echo "Removing signer files"
    rm -f root.crt signer_root.crt newcrl.pem new.key signer.key signer_only.crt \
        signer_issuing.crt signer.crt
}

genee_kem() {
    echo "Generating KEM certificate"
    openssl genpkey -algorithm "$OPENSSL_KEYALG" -out signer_leaf-key.pem -outpubkey signer_leaf-pubkey.pem
    openssl x509 -new -subj "/CN=signer-leaf" -CA signer_subinterCA-cert.pem -CAkey signer_subinterCA-key.pem \
        -out signer_leaf-cert.pem -force_pubkey signer_leaf-pubkey.pem -extensions SAN \
        -extfile <(printf "[SAN]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,keyEncipherment")
}

gen_signercert() {
    echo "Generating signer certificates"
    remove_signerfiles
    sleep 5
    OPENSSL_KEYALG=${signer_rootca_keyalg} \
    $mkcert_sh genroot "signer-rootCA" signer_root-key signer_root-cert
    OPENSSL_KEYALG=${signer_interca_keyalg} \
    $mkcert_sh genca "signer-interCA" signer_interCA-key signer_interCA-cert signer_root-key signer_root-cert
    OPENSSL_KEYALG=${signer_subinterca_keyalg} \
    $mkcert_sh genca "signer-subinterCA" signer_subinterCA-key signer_subinterCA-cert signer_interCA-key signer_interCA-cert

    OPENSSL_KEYALG=${signer_leaf_keyalg}
    if [[ "$signer_leaf_keyalg" == *"MLKEM"* ]]; then
        OPENSSL_KEYALG=${signer_leaf_keyalg} genee_kem
    else
        OPENSSL_KEYALG=${signer_leaf_keyalg} \
        $mkcert_sh genee -p clientAuth "signer-leaf" signer_leaf-key signer_leaf-cert signer_subinterCA-key signer_subinterCA-cert
    fi

    gen_demoCAfolder
    openssl ca -gencrl -keyfile signer_subinterCA-key.pem -cert signer_subinterCA-cert.pem -out signer_subinterCA-crl.pem -crldays 36525 \
            -config <(printf "[ca]\ndefault_ca= CA_default\n[CA_default]\n%s\n%s\n%s\n" \
		      "database = ./demoCA/index.txt" "crlnumber = ./demoCA/crlnumber" "default_md = default")
    cat signer_leaf-cert.pem signer_subinterCA-cert.pem signer_interCA-cert.pem > signer_chain.pem
    cat signer_subinterCA-cert.pem signer_interCA-cert.pem signer_root-cert.pem > signer_fullchain.pem
    openssl pkcs12 -export -out signer.p12 -inkey signer_leaf-key.pem -in signer_leaf-cert.pem -certfile signer_fullchain.pem -password pass:12345
    rm -f signer_fullchain.pem
    cat signer_subinterCA-cert.pem signer_interCA-cert.pem > signer_issuing-cert.pem
    rename_signerfiles
}



all() {
    gen_servercert
    gen_signercert
}

"$@"
