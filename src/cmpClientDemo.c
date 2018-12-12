/*!*****************************************************************************
 * @file   cmpClientDemo.c
 * @brief  generic CMP client library detailed usage demonstration
 *
 * @author David von Oheimb, CT RDA ITS SEA, David.von.Oheimb@siemens.com
 *
 * @copyright (c) Siemens AG 2018 all rights reserved
 ******************************************************************************/

#include <genericCMPClient.h>

enum use_case { imprint, bootstrap, update,
                revocation /* 'revoke' already defined in unistd.h */ };

SSL_CTX *setup_TLS(void)
{
    STACK_OF(X509_CRL) *crls = NULL;
    CREDENTIALS *tls_creds = NULL;
    SSL_CTX *tls = NULL;

    const char *trusted = "certs/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt";
    X509_STORE *truststore = STORE_load(trusted, "trusted certs for TLS level");
    if (truststore == NULL)
        goto err;

    const char *crls_files = "certs/crls/PPKIPlaygroundInfrastructureIssuingCAv10.crl"; /* TODO: should also work: "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+Infrastructure+Issuing+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" */
    crls = CRLs_load(crls_files, "CRLs for TLS level");
    if (crls == NULL)
        goto err;

    const X509_VERIFY_PARAM *vpm = NULL;
    const char *CRLs_url = NULL;
    const char *OCSP_url = NULL;
    const bool use_CDPs = false;
    const bool use_AIAs = true;
    if (!STORE_set_parameters(truststore, OPTIONAL vpm, crls,
                              use_CDPs, OPTIONAL CRLs_url,
                              use_AIAs, OPTIONAL OCSP_url))
        goto err;

    const char *certs = "certs/ppki_playground_tls.p12";
    const char *pkey = certs;
    tls_creds = CREDENTIALS_load(certs, pkey, "pass:12345", "credentials for TLS level");
    if (tls_creds == NULL)
        goto err;

    const char *ciphers = NULL; /* or, e.g., "HIGH:!ADH:!LOW:!EXP:!MD5:@STRENGTH"; */
    const int security_level = -1;
    tls = TLS_new(truststore, tls_creds, ciphers, security_level);

 err:
    if (tls == NULL)
        STORE_free(truststore);
    CRLs_free(crls);
    CREDENTIALS_free(tls_creds);
    return tls;
}

X509_STORE *setup_CMP_truststore(void)
{
    STACK_OF(X509_CRL) *crls = NULL;

    X509_STORE *cmp_truststore = NULL;
    const char *trusted_cert_files =
        "certs/trusted/PPKIPlaygroundECCRootCAv10.crt, "
        "certs/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt";
    cmp_truststore = STORE_load(trusted_cert_files, "trusted certs for CMP level");
    if (cmp_truststore == NULL)
        goto err;

    const char *crls_files =
        "certs/crls/PPKIPlaygroundInfrastructureRootCAv10.crl, "/* TODO: should also work: "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+Infrastructure+Root+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" */
        "certs/crls/PPKIPlaygroundECCRootCAv10.crl";/* TODO: should also work: "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+ECC+Root+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" */
    crls = CRLs_load(crls_files, "CRLs for CMP level");
    if (crls == NULL)
        goto err;

    const X509_VERIFY_PARAM *vpm = NULL;
    const char *CRLs_url = NULL;
    const char *OCSP_url = NULL;
    const bool use_CDPs = true;
    const bool use_AIAs = false;
    if (!STORE_set_parameters(cmp_truststore, OPTIONAL vpm, crls,
                              use_CDPs, OPTIONAL CRLs_url,
                              use_AIAs, OPTIONAL OCSP_url)) {
        STORE_free(cmp_truststore);
        cmp_truststore = NULL;
    }

err:
    CRLs_free(crls);
    /* X509_VERIFY_PARAM_free(vpm); */
    return cmp_truststore;
}

CMP_err prepare_CMP_client(CMP_CTX **pctx, OPTIONAL OSSL_cmp_log_cb_t log_fn,
                           OPTIONAL CREDENTIALS *cmp_creds, enum use_case use_case)

{
    X509_STORE *cmp_truststore = setup_CMP_truststore();
    if (cmp_truststore == NULL)
        return -1;

    const char *new_cert_trusted = "certs/trusted/PPKIPlaygroundECCRootCAv10.crt";
    X509_STORE *new_cert_truststore =
        STORE_load(new_cert_trusted, "trusted certs for verifying new cert");
    CMP_err err = -2;
    if (new_cert_truststore == NULL)
        goto err;

    STACK_OF(X509) *untrusted = NULL; /* TODO: add helper function */
    const char *digest = "sha256";
    OSSL_cmp_transfer_cb_t transfer_fn = NULL; /* default HTTP(S) transfer */
    const int total_timeout = 100;
    const bool implicit_confirm = use_case == update;
    err = CMPclient_prepare(pctx, OPTIONAL log_fn,
                            cmp_truststore, OPTIONAL untrusted,
                            cmp_creds, digest,
                            OPTIONAL transfer_fn, total_timeout,
                            new_cert_truststore, implicit_confirm);
    sk_X509_pop_free(untrusted, X509_free); /* TODO: add helper function */
    STORE_free(new_cert_truststore);
 err:
    STORE_free(cmp_truststore);
    return err;
}

X509_EXTENSIONS *setup_X509_extensions(void)
{
    X509_EXTENSIONS *exts = EXTENSIONS_new();
    if (exts == NULL)
        return NULL;
    BIO *policy_sections = BIO_new(BIO_s_mem());
    if (policy_sections == NULL ||
        !EXTENSIONS_add_SANs(exts, "localhost, 127.0.0.1, 192.168.0.1") ||
        !EXTENSIONS_add_ext(exts, "keyUsage", "critical, digitalSignature", NULL) ||
        !EXTENSIONS_add_ext(exts, "extendedKeyUsage", "critical, serverAuth, "
                                  "1.3.6.1.5.5.7.3.2"/* clientAuth */, NULL) ||
        BIO_printf(policy_sections, "%s",
                   "[pkiPolicy]\n"
                   "  policyIdentifier = 1.3.6.1.4.1.4329.38.4.2.2\n"
                   "  CPS.1 = http://www.siemens.com/pki-policy/\n"
                   "  userNotice.1 = @notice\n"
                   "[notice]\n"
                   "  explicitText=Siemens policy text\n") <= 0 ||
        !EXTENSIONS_add_ext(exts, "certificatePolicies",
                            "critical, @pkiPolicy", policy_sections)) {
            EXTENSIONS_free(exts);
            exts = NULL;
    }
    BIO_free(policy_sections);
    return exts;
}

static int CMPclient_demo(enum use_case use_case)
{
    OSSL_cmp_log_cb_t log_fn = NULL;
    CMP_err err = CMPclient_init(log_fn);
    if (err != CMP_OK)
        return err;

    CMP_CTX *ctx = NULL;
    SSL_CTX *tls = NULL;
    EVP_PKEY *new_key = NULL;
    X509_EXTENSIONS *exts = NULL;
    CREDENTIALS *new_creds = NULL;

    CREDENTIALS *cmp_creds = NULL;
    if (use_case == imprint || use_case == bootstrap) { /* TODO: use different creds for imprinting */
        const char *certs = "certs/ppki_playground_cmp_signer.p12";
        const char *pkey = certs;
        const char *source = "pass:12345";
        cmp_creds = CREDENTIALS_load(certs, pkey, source, "credentials for CMP level");
    } else if (use_case == update || use_case == revocation) {
        const char *certs = "certs/new.crt";
        const char *pkey = "certs/new.pem";
        const char *source = NULL /* unencrypted key input file */;
        cmp_creds = CREDENTIALS_load(certs, pkey, source, "credentials for CMP level");
    }
    if (cmp_creds == NULL) {
        err = -4;
        goto err;
    }

    err = prepare_CMP_client(&ctx, log_fn, cmp_creds, use_case);
    if (err != CMP_OK) {
        goto err;
    }

    /* direct call of CMP API: accept negative responses without protection */
    (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_UNPROTECTED_ERRORS, 1);
    /* direct call of CMP API: accept non-enabled key usage digitalSignature */
    (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_IGNORE_KEYUSAGE, 1);

    tls = setup_TLS();
    if (tls == NULL) {
        err = -5;
        goto err;
    }
    const char *server = "ppki-playground.ct.siemens.com:443";
    const char *path = (use_case == imprint || use_case == bootstrap)
        ?  "/ejbca/publicweb/cmp/PlaygroundECC"
        :  "/ejbca/publicweb/cmp/PlaygroundCMPSigning";
    const int timeout = 10;
    err = CMPclient_setup_HTTP(ctx, server, path, timeout, tls, NULL/* proxy */);
    if (err != CMP_OK) {
        goto err;
    }

    const char *subject = "/CN=test-genCMPClientDemo_detailed/OU=PPKI Playground"
        "/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE";
    if (use_case != revocation) {
        new_key = KEY_new("EC:secp521r1");
        if (new_key == NULL) {
            err = -6;
            goto err;
        }
    }
    if ((use_case == imprint || use_case == bootstrap) 
        && (exts = setup_X509_extensions()) == NULL) {
        err = -7;
        goto err;
    }

    switch (use_case) {
    case imprint:
        err = CMPclient_imprint(ctx, &new_creds, new_key, subject, exts);
        break;
    case bootstrap:
        err = CMPclient_bootstrap(ctx, &new_creds, new_key, subject, exts);
        break;
    case update:
        err = CMPclient_update(ctx, &new_creds, new_key);
        break;
    case revocation:
        err = CMPclient_revoke(ctx, CREDENTIALS_get_cert(cmp_creds), CRL_REASON_NONE);
        break;
    default:
        err = -8;
    }
    if (err != CMP_OK) {
        goto err;
    }

    if (use_case != revocation) {
        const char *cert_file = "certs/new.crt";
        const char *key_file = "certs/new.pem";
        const char *source = NULL /* unencrypted key output file */;
        const char *desc = "newly enrolled certificate and related key and chain";
        if (!CREDENTIALS_save(new_creds, cert_file, key_file, OPTIONAL source, desc)) {
            err = -9;
            goto err;
        }
    }

 err:
    CMPclient_finish(ctx);
    TLS_free(tls);
    KEY_free(new_key);
    EXTENSIONS_free(exts);
    CREDENTIALS_free(new_creds);
    CREDENTIALS_free(cmp_creds);

#ifndef CLOSE_LOG_ON_EACH_FINISH
    LOG_close();
#endif

    if (err != CMP_OK) {
        fprintf(stderr, "CMPclient error %d\n", err);
    }
    return err;
}

int main(int argc, char *argv[])
{
    enum use_case use_case = bootstrap; /* default */
    if (argc > 1) {
        if (argc == 2 && !strcmp(argv[1], "imprint"))
            use_case = imprint;
        else if (argc == 2 && !strcmp(argv[1], "bootstrap"))
            use_case = bootstrap;
        else if (argc == 2 && !strcmp(argv[1], "update"))
            use_case = update;
        else if (argc == 2 && !strcmp(argv[1], "revoke"))
            use_case = revocation;
        else {
            fprintf(stderr, "Usage: %s [imprint | bootstrap | update | revoke]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }
    return CMPclient_demo(use_case) == CMP_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
