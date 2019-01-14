/*!*****************************************************************************
 * @file   cmpClientDemo.c
 * @brief  generic CMP client library detailed usage demonstration
 *
 * @author David von Oheimb, CT RDA ITS SEA, David.von.Oheimb@siemens.com
 *
 * @copyright (c) Siemens AG 2018 all rights reserved
 ******************************************************************************/

#include <string.h>

#include <genericCMPClient.h>

#ifdef LOCAL_DEFS
X509 *CREDENTIALS_get_cert(const CREDENTIALS *creds);
#endif

enum use_case { imprint, bootstrap, update,
                revocation /* 'revoke' already defined in unistd.h */ };

#define TRUST_DIR "creds/trusted/"
#define CRL_DIR   "creds/crls/"

#define KEYTYPE "ECC" /* or "RSA" */
#define RSA_SPEC "RSA:2048"
#define ECC_SPEC "EC:prime256v1"

const char *const digest = "sha256";

const char *const new_certs = "creds/new.crt";
const char *const new_key   = "creds/new.pem";
const char *const new_key_pass = NULL; /* or, e.g., "pass:12345", or "engine:id" */

#ifdef INSTA /* http://pki.certificate.fi:8080/enroll-ca-list.html */

#define ROOT_CA        "InstaDemoCA"
#define INFR_ROOT_CA    ROOT_CA
#define INFR_ISSUING_CA ROOT_CA

// #undef CRL_DIR

const char *const recipient = "/C=FI/O=Insta Demo/CN=Insta Demo CA";
const char *const subject = "/CN=test-genCMPClientDemo";

const char *const pbm_secret = "insta";
const char *const pbm_ref = "3078";


#define INSTA_P12 "creds/insta_client.p12"
const char *const cmp_certs = INSTA_P12;
const char *const cmp_key   = INSTA_P12;
const char *const cmp_key_pass = NULL;

const char *const tls_certs = INSTA_P12;
const char *const tls_key   = INSTA_P12;
const char *const tls_key_pass = NULL;

#define INI_PATH "pkix/"
#define UPD_PATH INI_PATH
#define     SERVER "pki.certificate.fi:8700"
#define TLS_SERVER SERVER
const char *const proxy = NULL; /* or, e.g., "test.coia.siemens.net:9400" */
const bool use_tls = false;

#else

#define      ROOT_CA    "PPKIPlayground"KEYTYPE"RootCAv10"
#define INFR_ROOT_CA    "PPKIPlaygroundInfrastructureRootCAv10"
#define INFR_ISSUING_CA "PPKIPlaygroundInfrastructureIssuingCAv10"

const char *const recipient = "/CN=PPKI Playground "KEYTYPE" Issuing CA v1.0"
    "/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE";
const char *const subject = "/CN=test-genCMPClientDemo/OU=PPKI Playground"
        "/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE";

const char *const pbm_secret = "SecretCmp";
const char *const pbm_ref = NULL;

#define CMP_P12 "creds/ppki_playground_cmp_signer.p12"
const char *const cmp_certs = CMP_P12;
const char *const cmp_key   = CMP_P12;
const char *const cmp_key_pass = "pass:12345";

#define TLS_P12 "creds/ppki_playground_tls.p12"
const char *const tls_certs = TLS_P12;
const char *const tls_key   = TLS_P12;
const char *const tls_key_pass = "pass:12345";

#define INI_PATH "/ejbca/publicweb/cmp/Playground"KEYTYPE
#define UPD_PATH "/ejbca/publicweb/cmp/PlaygroundCMPSigning"
#define SRV_NAME "ppki-playground.ct.siemens.com"
#define     SERVER SRV_NAME":80"
#define TLS_SERVER SRV_NAME":443"
const char *const proxy = NULL;
const bool use_tls = true;

#endif

const char *const untrusted = NULL;

const char *tls_ciphers = NULL; /* or, e.g., "HIGH:!ADH:!LOW:!EXP:!MD5:@STRENGTH"; */

SSL_CTX *setup_TLS(void)
{
    STACK_OF(X509_CRL) *crls = NULL;
    CREDENTIALS *tls_creds = NULL;
    SSL_CTX *tls = NULL;

    const char *trusted = TRUST_DIR INFR_ROOT_CA".crt";
    X509_STORE *truststore = STORE_load(trusted, "trusted certs for TLS level");
    if (truststore == NULL)
        goto err;
    /* TODO maybe also add untrusted TLS certs */

#ifdef CRL_DIR
    const char *crls_files = CRL_DIR INFR_ISSUING_CA".crl";
    crls = CRLs_load(crls_files, "CRLs for TLS level");
    if (crls == NULL)
        goto err;
#endif

    const X509_VERIFY_PARAM *vpm = NULL;
    const char *CRLs_url = NULL;
    const char *OCSP_url = NULL;
    const bool use_CDPs = false;
    const bool use_AIAs = true;
    if (!STORE_set_parameters(truststore, OPTIONAL vpm, crls,
                              use_CDPs, OPTIONAL CRLs_url,
                              use_AIAs, OPTIONAL OCSP_url))
        goto err;

    tls_creds = CREDENTIALS_load(tls_certs, tls_key, tls_key_pass,
                                 "credentials for TLS level");
    if (tls_creds == NULL)
        goto err;

    const int security_level = -1;
    tls = TLS_new(truststore, tls_creds, tls_ciphers, security_level);

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

#ifdef CRL_DIR
    const char *crls_files = CRL_DIR ROOT_CA".crl, "
                             CRL_DIR INFR_ROOT_CA".crl";
    crls = CRLs_load(crls_files, "CRLs for CMP level");
    if (crls == NULL)
        goto err;
#endif

    const char *trusted_cert_files = TRUST_DIR ROOT_CA".crt, "
                                     TRUST_DIR INFR_ROOT_CA".crt";
    cmp_truststore = STORE_load(trusted_cert_files, "trusted certs for CMP level");
    if (cmp_truststore == NULL)
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

    const char *new_cert_trusted = TRUST_DIR ROOT_CA".crt";
    X509_STORE *new_cert_truststore =
        STORE_load(new_cert_trusted, "trusted certs for verifying new cert");
    CMP_err err = -2;
    if (new_cert_truststore == NULL)
        goto err;

    STACK_OF(X509) *untrusted_certs = untrusted == NULL ? NULL :
        CERTS_load(untrusted, "untrusted certs for CMP");
    OSSL_cmp_transfer_cb_t transfer_fn = NULL; /* default HTTP(S) transfer */
    const int total_timeout = 100;
    const bool implicit_confirm = use_case == update;
    err = CMPclient_prepare(pctx, OPTIONAL log_fn,
                            cmp_truststore, OPTIONAL recipient,
                            OPTIONAL untrusted_certs,
                            cmp_creds, digest,
                            OPTIONAL transfer_fn, total_timeout,
                            new_cert_truststore, implicit_confirm);
    CERTS_free(untrusted_certs);
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
    EVP_PKEY *new_pkey = NULL;
    X509_EXTENSIONS *exts = NULL;
    CREDENTIALS *new_creds = NULL;

    const char *const creds_desc = "credentials for CMP level";
    CREDENTIALS *cmp_creds =
        use_case == imprint ? CREDENTIALS_new(NULL, NULL, NULL, pbm_secret, pbm_ref) :
        use_case == bootstrap ? CREDENTIALS_load(cmp_certs, cmp_key, cmp_key_pass, creds_desc)
                              : CREDENTIALS_load(new_certs, new_key, new_key_pass, creds_desc);
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

    if (use_tls && (tls = setup_TLS()) == NULL) {
        err = -5;
        goto err;
    }
    const char *path = (use_case == imprint ||
                        use_case == bootstrap) ? INI_PATH : UPD_PATH;
    const int timeout = 10;
    const char *server = use_tls ? TLS_SERVER : SERVER;
    err = CMPclient_setup_HTTP(ctx, server, path, timeout, tls, proxy);
    if (err != CMP_OK) {
        goto err;
    }

    if (use_case != revocation) {
        const char *key_spec = !strcmp(KEYTYPE, "RSA") ? RSA_SPEC : ECC_SPEC;
        new_pkey = KEY_new(key_spec);
        if (new_pkey == NULL) {
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
        err = CMPclient_imprint(ctx, &new_creds, new_pkey, subject, exts);
        break;
    case bootstrap:
        err = CMPclient_bootstrap(ctx, &new_creds, new_pkey, subject, exts);
        break;
    case update:
        err = CMPclient_update(ctx, &new_creds, new_pkey);
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
        const char *new_desc = "newly enrolled certificate and related key and chain";
        if (!CREDENTIALS_save(new_creds, new_certs, new_key, new_key_pass, new_desc)) {
            err = -9;
            goto err;
        }
    }

 err:
    CMPclient_finish(ctx);
    TLS_free(tls);
    KEY_free(new_pkey);
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
