/*!*****************************************************************************
 * @file   cmpClientDemo.c
 * @brief  generic CMP client library detailed usage demonstration
 *
 * @author David von Oheimb, CT RDA ITS SEA, David.von.Oheimb@siemens.com
 *
 * @copyright (c) Siemens AG 2018 all rights reserved
 ******************************************************************************/

#include <genericCMPClient.h>

static int CMPclient_demo(void)
{
    X509_STORE *cmp_truststore = NULL;
    CREDENTIALS *creds = NULL;
    X509_STORE *new_cert_truststore = NULL;
    OSSL_CMP_CTX *ctx = NULL;
    X509_STORE *tls_truststore = NULL;
    CREDENTIALS *tls_creds = NULL;
    SSL_CTX *tls = NULL;
    EVP_PKEY *new_key = NULL;
    X509_EXTENSIONS *exts = NULL;
    CREDENTIALS *new_creds = NULL;

    OSSL_cmp_log_cb_t log_fn = NULL;
    CMP_err err = CMPclient_init(log_fn);
    if (err != CMP_OK) {
        fprintf(stderr, "failed to initialize genCMPClient\n");
        return err;
    }

    STACK_OF(X509) *untrusted = NULL;
    {
        {
            const char *file =
                "certs/trusted/PPKIPlaygroundECCRootCAv10.crt, "
                "certs/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt";
            cmp_truststore = STORE_load(file, "trusted certs for CMP level");
        }
        if (cmp_truststore == NULL) {
            err = -1;
            goto err;
        }
        const X509_VERIFY_PARAM *vpm = NULL;
        STACK_OF(X509_CRL) *crls = NULL;
        {
            const char *file =
                "certs/crls/PPKIPlaygroundInfrastructureRootCAv10.crl, "/* TODO: should also work: "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+Infrastructure+Root+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" */
                "certs/crls/PPKIPlaygroundECCRootCAv10.crl";/* TODO: should also work: "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+ECC+Root+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" */

            crls = CRLs_load(file, "CRLs for CMP level");
        }
        const char *CRLs_url = NULL;
        const char *OCSP_url = NULL;
        if (crls == NULL ||
            !STORE_set_parameters(cmp_truststore, OPTIONAL vpm, crls,
                                  true /* use_CDPs */, OPTIONAL CRLs_url, 
                                  false/* use_AIAs */, OPTIONAL OCSP_url)) {
            err = -1;
            goto err;
        }
    }
    {
        const char *certs = "certs/ppki_playground_cmp_signer.p12";
        const char *pkey = certs;
        creds = CREDENTIALS_load(certs, pkey, "pass:12345", "credentials for CMP level");
    }
    const char *digest = "sha256";
    OSSL_cmp_transfer_cb_t transfer_fn = NULL; /* default HTTP(S) transfer */
    int total_timeout = 100;
    {
        const char *file = "certs/trusted/PPKIPlaygroundECCRootCAv10.crt";
        new_cert_truststore = STORE_load(file, "trusted certs for verifying new cert");
    }
    if (creds == NULL || new_cert_truststore == NULL) {
        err = -2;
        goto err;
    }

    err = CMPclient_prepare(&ctx, OPTIONAL log_fn,
                            cmp_truststore, OPTIONAL untrusted,
                            creds, digest,
                            OPTIONAL transfer_fn, total_timeout,
                            new_cert_truststore, false/* implicit_confirm */);
    if (err != CMP_OK) {
        goto err;
    }

    /* direct call of CMP API: accept negative responses without protection */
    (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_UNPROTECTED_ERRORS, 1);
    /* direct call of CMP API: accept non-enabled key usage digitalSignature */
    (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_IGNORE_KEYUSAGE, 1);

    const char *server = "ppki-playground.ct.siemens.com:443";
    const char *path = "/ejbca/publicweb/cmp/PlaygroundECC";
    int timeout = 10;
    {
        {
            const char *file = "certs/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt";
            tls_truststore = STORE_load(file, "trusted certs for TLS level");
        }
        const X509_VERIFY_PARAM *vpm = NULL;
        STACK_OF(X509_CRL) *crls = NULL;
        {
            const char *file = "certs/crls/PPKIPlaygroundInfrastructureIssuingCAv10.crl"; /* TODO: should also work: "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+Infrastructure+Issuing+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" */
            crls = CRLs_load(file, "CRLs for TLS level");
        }
        const char *CRLs_url = NULL;
        const char *OCSP_url = NULL;
        if (tls_truststore == NULL || crls == NULL ||
            !STORE_set_parameters(tls_truststore, OPTIONAL vpm, crls,
                                  true /* use_CDPs */, OPTIONAL CRLs_url,
                                  false/* use_AIAs */, OPTIONAL OCSP_url)) {
            err = -3;
            goto err;
        }
    }
    {
        const char *tls_certs = "certs/ppki_playground_tls.p12";
        const char *tls_pkey = tls_certs;
        tls_creds = CREDENTIALS_load(tls_certs, tls_pkey, "pass:12345", "credentials for TLS level");
        if (tls_creds == NULL) {
            err = -4;
            goto err;
        }
    }
    const char *ciphers = NULL; /* or, e.g., "HIGH:!ADH:!LOW:!EXP:!MD5:@STRENGTH"; */
    tls = TLS_new(tls_truststore, tls_creds, ciphers, -1);
    if (tls == NULL) {
        err = -5;
        goto err;
    }
    err = CMPclient_setup_HTTP(ctx, server, path, timeout, tls, NULL/* proxy */);
    if (err != CMP_OK) {
        goto err;
    }

    const char *subject = "/CN=test-genCMPClientDemo_detailed/OU=PPKI Playground"
        "/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE";
    new_key = KEY_new("EC:secp521r1");
    if (new_key == NULL) {
        err = -6;
        goto err;
    }
    {
        exts = EXTENSIONS_new();
        BIO *policy_sections = BIO_new(BIO_s_mem());
        if (exts == NULL || policy_sections == NULL ||
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
            BIO_free(policy_sections);
            EXTENSIONS_free(exts);
            err = -7;
            goto err;
        }
        BIO_free(policy_sections);
    }
    err = CMPclient_bootstrap(ctx, &new_creds, new_key, subject, exts);
    if (err != CMP_OK) {
        goto err;
    }

    {
        const char *cert_file = "certs/new.crt";
        const char *key_file = "certs/new.pem";
        const char *source = NULL/* plain file */;
        const char *desc = "newly enrolled certificate and related key and chain";
        if (!CREDENTIALS_save(new_creds, cert_file, key_file, OPTIONAL source, desc)) {
            err = -8;
            goto err;
        }
    }

 err:
    CMPclient_finish(ctx);
    if (err != CMP_OK) {
        fprintf(stderr, "CMPclient error %d\n", err);
    }
    CREDENTIALS_free(new_creds);
    EXTENSIONS_free(exts);
    KEY_free(new_key);
    TLS_free(tls);
    CREDENTIALS_free(tls_creds);
    STORE_free(tls_truststore);
    STORE_free(new_cert_truststore);
    STORE_free(cmp_truststore);
    CREDENTIALS_free(creds);
#ifndef CLOSE_LOG_ON_EACH_FINISH
    LOG_close();
#endif

    return err;
}

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
    return CMPclient_demo() == CMP_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
