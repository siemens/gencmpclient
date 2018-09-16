/*!*****************************************************************************
 * @file   cmpClientDemo.c
 * @brief  generic CMP client library usage demonstration
 *
 * @author David von Oheimb, CT RDA ITS SEA, David.von.Oheimb@siemens.com
 *
 * @copyright (c) Siemens AG 2018 all rights reserved
 ******************************************************************************/

#include <SecUtils/credentials/verify.h>
#include <SecUtils/storage/files.h>
#include <genericCMPClient.h>

static int CMPclient_demo(void)
{
    CMP_err err = CMP_OK;

    CMP_CTX *ctx = NULL;
    cmp_log_cb_t log_fn = NULL;
    X509_STORE *cmp_truststore = NULL;
    STACK_OF(X509) *untrusted = NULL;
    {
        {
            const char *file = "certs/trusted/PPKIPlaygroundECCRootCAv10.crt, "
                "certs/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt";
            const char *desc = "trusted certs for CMP level";
            cmp_truststore = STORE_load(file, OPTIONAL desc);
        }
        const X509_VERIFY_PARAM *vpm = NULL;
        STACK_OF(X509_CRL) *crls = NULL;
        {
            const char *file = "certs/crls/PPKIPlaygroundInfrastructureRootCAv10.crl, "/* TODO: should also work: "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+Infrastructure+Root+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE " */
                "certs/crls/PPKIPlaygroundECCRootCAv10.crl";

            const char *desc = "CRLs for CMP level";
            crls = CRLs_load(file, OPTIONAL desc);
        }
        const char *CRLs_url = NULL;
        bool use_CDPs = true;
        const char *OCSP_url = NULL;
        bool use_AIAs = false;
        if (!cmp_truststore || !crls ||
            !STORE_set_parameters(cmp_truststore, OPTIONAL vpm, OPTIONAL crls, 
                                  OPTIONAL CRLs_url, use_CDPs,
                                  OPTIONAL OCSP_url, use_AIAs)) {
            err = -1;
            goto err;
        }
    }
    CREDENTIALS *creds = NULL;
    {
        const char *certs = "certs/ppki_playground_cmp_signer.p12";
        const char *pkey = certs;
        const char *source = "pass:12345";
        const char *desc = "credentials for CMP level";
        creds = CREDENTIALS_load(certs, pkey, OPTIONAL source, OPTIONAL desc);
        if (!creds) {
            err = -2;
            goto err;
        }
    }
    const char *digest = "sha256";
    cmp_transfer_cb_t transfer_fn = NULL; /* default HTTP(S) transfer */
    int total_timeout = 100;
    X509_STORE *new_cert_truststore = NULL;
    {
        const char *file = "certs/trusted/PPKIPlaygroundECCRootCAv10.crt";
        const char *desc = "trusted certs for verifying new cert";
        new_cert_truststore = STORE_load(file, OPTIONAL desc);
    }

    bool implicit_confirm = false;
    err = CMPclient_prepare(&ctx, OPTIONAL log_fn,
                            OPTIONAL cmp_truststore, OPTIONAL untrusted,
                            OPTIONAL creds, OPTIONAL digest,
                            OPTIONAL transfer_fn, total_timeout,
                            OPTIONAL new_cert_truststore, implicit_confirm);
    if (err != CMP_OK) {
        goto err;
    }

    /* direct call of CMP API: accept negative responses without protection */
    (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_UNPROTECTED_ERRORS, 1);
    /* direct call of CMP API: accept non-enabled key usage digitalSignature */
    (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_IGNORE_KEYUSAGE, 1);

    const char *server = "ppki-playground.ct.siemens.com:443";
    const char *path = "/ejbca/publicweb/cmp/PlaygroundECC";
    int timeout = 10;
    X509_STORE *tls_truststore = NULL;
    {
        {
            const char *file = "certs/trusted/PPKIPlaygroundInfrastructureRootCAv10.crt";
            const char *desc = "trusted certs for TLS level";
            tls_truststore = STORE_load(file, OPTIONAL desc);
        }
        const X509_VERIFY_PARAM *vpm = NULL;
        STACK_OF(X509_CRL) *crls = NULL;
        {
            const char *file = "certs/crls/PPKIPlaygroundInfrastructureIssuingCAv10.crl";
            const char *desc =  "CRLs for TLS level";
            crls = CRLs_load(file, OPTIONAL desc);
        }
        const char *CRLs_url = NULL;
        bool use_CDPs = true;
        const char *OCSP_url = NULL;
        bool use_AIAs = false;
        if (!tls_truststore || !crls ||
            !STORE_set_parameters(tls_truststore, OPTIONAL vpm,
                                  OPTIONAL crls,
                                  OPTIONAL CRLs_url, use_CDPs,
                                  OPTIONAL OCSP_url, use_AIAs)) {
            err = -3;
            goto err;
        }
    }
    CREDENTIALS *tls_creds = NULL;
    {
        const char *tls_certs = "certs/ppki_playground_tls.p12";
        const char *tls_pkey = tls_certs;
        const char *tls_source = "pass:12345";
        const char *tls_desc = "credentials for TLS level";
        tls_creds = CREDENTIALS_load(tls_certs, tls_pkey, OPTIONAL tls_source, OPTIONAL tls_desc);
        if (!tls_creds) {
            err = -4;
            goto err;
        }
    }
    char *ciphers = "HIGH:!ADH:!LOW:!EXP:!MD5:@STRENGTH";
    SSL_CTX *tls = TLS_new(OPTIONAL tls_truststore, OPTIONAL tls_creds, OPTIONAL ciphers);
    err = CMPclient_setup_HTTP(ctx, server, path, timeout, OPTIONAL tls, NULL/* proxy */);
    if (err != CMP_OK) {
        goto err;
    }

    CREDENTIALS *new_creds = NULL;
    const char *subject = "/CN=test-API/OU=PPKI Playground"
        "/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE";
    EVP_PKEY *new_key = KEY_new("secp521r1");
    if (new_key == NULL) {
        err = -5;
        goto err;
    }
    X509_EXTENSIONS *exts = NULL;
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
            err = -6;
            goto err;
        }
        BIO_free(policy_sections);
    }
    err = CMPclient_bootstrap(ctx, &new_creds, new_key, subject, OPTIONAL exts);
    if (err != CMP_OK) {
        goto err;
    }
    {
        const CREDENTIALS *creds = new_creds;
        const char *file = "certs/new.p12";
        const char *source = NULL/* plain file */;
        const char *desc = "credentials including newly enrolled certificate";
        if (!CREDENTIALS_save(creds, file, OPTIONAL source, OPTIONAL desc) ||
            !FILES_store_cert(creds->cert, "certs/new.crt", FORMAT_PEM, "newly enrolled cert")) {
            goto err;
        }
    }

 err:
    if (err != CMP_OK) {
        fprintf(stderr, "CMPclient error %d\n", err);
        ERR_print_errors_fp(stderr);
    }
    CMPclient_finish(ctx);
    CREDENTIALS_free(new_creds);
    EXTENSIONS_free(exts);
    KEY_free(new_key);
    /* TODO: crash on deallocation - double free?
    TLS_free(tls);*/
    CREDENTIALS_free(tls_creds);
    STORE_free(tls_truststore);
    STORE_free(new_cert_truststore);
    CREDENTIALS_free(creds);
    STORE_free(cmp_truststore);

    return err;
}

int main(int argc, char *argv[])
{
    return CMPclient_demo() == CMP_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
