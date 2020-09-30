/*-
 * @file   cmpClient.c
 * @brief  generic CMP client library demo/test client
 *
 * @author David von Oheimb, CT RDA CST SEA, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2018-2020 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 *  SPDX-License-Identifier: Apache-2.0
 */


#include <securityUtilities.h>
#include <SecUtils/config/config.h>
//#include <SecUtils/util/log.h>
#include <SecUtils/certstatus/crls.h> /* just for use in test_load_crl_cb() */
#include <SecUtils/certstatus/crl_mgmt.h>
#include <SecUtils/util/cdp_util.h> /* TODO integrate with util.h */

#include <genericCMPClient.h>

#include <openssl/ssl.h>

/* needed for OSSL_CMP_ITAV_gen() in function CMPclient(), TODO remove */
#include "../cmpossl/crypto/cmp/cmp_local.h"


#ifdef LOCAL_DEFS
# include "genericCMPClient_use.h"
#endif

/* Usecases are split between CMP usecases and local usecases.
 * Local usecases do not communicate with CMP and therefore don't
 * need its complex setup.
 */
enum use_case { no_use_case,
                /* start with cmp use cases */
                imprint, bootstrap, check_originality, pkcs10, update,
                revocation /* 'revoke' already defined in unistd.h */, genm,
                default_case,
                /* continue with local use cases cmp_usecases for comparison */
                cmp_usecases = default_case,
                check_revocation_status
};

#define RSA_SPEC "RSA:2048"
#define ECC_SPEC "EC:prime256v1"

#define CONFIG_DEFAULT "config/demo.cnf"
char *opt_config = CONFIG_DEFAULT; /* OpenSSL-style configuration file */
CONF *config = NULL; /* OpenSSL configuration structure */
char *opt_section = "EJBCA"; /* name(s) of config file section(s) to use */
#define DEFAULT_SECTION "default"
char demo_sections[80];
long opt_verbosity;

const char *opt_server;
const char *opt_proxy;
const char *opt_no_proxy;
const char *opt_cdp_proxy;
const char *opt_crl_cache_dir;

const char *opt_path;
long opt_msg_timeout;
long opt_total_timeout;

const char *opt_trusted;
const char *opt_untrusted;
const char *opt_srvcert;
const char *opt_recipient;
const char *opt_expect_sender;
bool opt_ignore_keyusage;
bool opt_unprotected_errors;
const char *opt_extracertsout;
const char *opt_extracerts_dir;
const char *opt_extracerts_dir_format;
const char *opt_cacertsout;
const char *opt_cacerts_dir;
const char *opt_cacerts_dir_format;

const char *opt_ref;
const char *opt_secret;
/* TODO re-add creds */
const char *opt_cert;
const char *opt_own_trusted;
const char *opt_key;
const char *opt_keypass;
const char *opt_digest;
const char *opt_mac;
const char *opt_extracerts;
bool opt_unprotected_requests;

const char *opt_cmd; /* TODO? add genm */
const char *opt_infotype;
static int infotype = NID_undef;
const char *opt_geninfo;

const char *opt_newkeytype;
const char *opt_newkey;
const char *opt_newkeypass;
const char *opt_subject;
const char *opt_issuer;
long opt_days;
const char *opt_reqexts;
char *opt_sans;
bool opt_san_nodefault;
const char *opt_policies;
char *opt_policy_oids;
bool opt_policy_oids_critical;
long opt_popo;
const char *opt_csr;
const char *opt_out_trusted;
bool opt_implicit_confirm;
bool opt_disable_confirm;
const char *opt_certout;
const char *opt_chainout;

const char *opt_oldcert;
long opt_revreason;

/* TODO? add credentials format options */
/* TODO add opt_engine */

bool opt_tls_used;
/* TODO re-add tls_creds */
const char *opt_tls_cert;
const char *opt_tls_key;
const char *opt_tls_keypass;
const char *opt_tls_extra;
const char *opt_tls_trusted;
const char *opt_tls_host;

static char *opt_reqin = NULL;
static char *opt_reqout = NULL;
static char *opt_rspin = NULL;
static char *opt_rspout = NULL;

/* TODO further extend verification options and align with cmpossl/apps/cmp.c */
bool opt_check_all;
bool opt_check_any;
const char *opt_crls;
bool opt_use_cdp;
const char *opt_cdps;
long opt_crls_timeout;
size_t opt_crl_maxdownload_size;
bool opt_use_aia;
const char *opt_ocsp;
long opt_ocsp_timeout;
bool opt_ocsp_last;
bool opt_stapling;

X509_VERIFY_PARAM *vpm = NULL;
CRLMGMT_DATA *cmdat_tls = NULL;
CRLMGMT_DATA *cmdat_new = NULL;
STACK_OF(X509_CRL) *crls = NULL;

opt_t cmp_opts[] = {
    { "help", OPT_BOOL, {.num = -1}, { NULL },
      "Display this summary"},
    { "config", OPT_TXT, {.txt = NULL}, { NULL },
      "Configuration file to use. \"\" means none. Default 'config/demo.cnf'"},
    { "section", OPT_TXT, {.txt = NULL}, { NULL },
      "Section(s) in config file to use. \"\" means 'default'. Default 'EJBCA'"},
    { "verbosity", OPT_NUM, {.num = LOG_INFO}, { (const char **) &opt_verbosity},
      "Logging level; 3=ERR, 4=WARN, 6=INFO, 7=DEBUG, 8=TRACE. Default 6 = INFO"},

    OPT_HEADER("Message transfer"),
    { "server", OPT_TXT, {.txt = NULL}, { &opt_server },
      "[http[s]://]address[:port][/path] of CMP server. Default port 80 or 443."},
    OPT_MORE("address may be a DNS name or an IP address; path can be overridden by -path"),
    { "proxy", OPT_TXT, {.txt = NULL}, { &opt_proxy },
      "[http[s]://]address[:port][/path] of HTTP(S) proxy. Default port 80; path is ignored."},
    OPT_MORE("Default from environment variable 'http_proxy', else 'HTTP_PROXY'"),
    { "no_proxy", OPT_TXT, {.txt = NULL}, { &opt_no_proxy },
      "List of addresses of servers not use HTTP(S) proxy for."},
    OPT_MORE("Default from environment variable 'no_proxy', else 'NO_PROXY', else none"),
    { "cdp_proxy", OPT_TXT, {.txt = NULL}, { &opt_cdp_proxy },
      "Address of the proxy server to use for getting CRLs."},
    OPT_MORE("Default from environment variable 'cdp_proxy', else 'CDP_PROXY', else none"),
    { "crl_cache_dir", OPT_TXT, {.txt = NULL}, { &opt_crl_cache_dir },
      "Directory of the CRL cache when downloaded during verification."},
    { "path", OPT_TXT, {.txt = NULL}, { &opt_path },
      "HTTP path (aka CMP alias) at the CMP server.  Default from -server, else \"/\""},
    { "msg_timeout", OPT_NUM, {.num = 120}, { (const char **)&opt_msg_timeout },
      "Timeout per CMP message round trip (or 0 for none). Default 120 seconds"},
    { "total_timeout", OPT_NUM, {.num = 0}, { (const char **)&opt_total_timeout},
      "Overall time an enrollment incl. polling may take. Default: 0 = infinite"},

    OPT_HEADER("Server authentication"),
    { "trusted", OPT_TXT, {.txt = NULL}, { &opt_trusted },
      "Certificates to trust as chain roots when verifying signed CMP responses"},
    { "untrusted", OPT_TXT, {.txt = NULL}, { &opt_untrusted },
      "Intermediate CA certs for chain construction for CMP/TLS/enrolled certs"},
    { "srvcert", OPT_TXT, {.txt = NULL}, { &opt_srvcert },
      "Server cert to pin and trust directly when verifying signed CMP responses"},
    { "recipient", OPT_TXT, {.txt = NULL}, { &opt_recipient },
      "DN of CA. Default: -srvcert subject, -issuer, issuer of -oldcert or -cert,"},
    OPT_MORE("subject of the first -untrusted cert if any, or else the NULL-DN"),
    { "expect_sender", OPT_TXT, {.txt = NULL}, { &opt_expect_sender },
      "DN of expected sender of responses. Defaults to subject of -srvcert, if any"},
    { "ignore_keyusage", OPT_BOOL, {.bit = false}, { (const char **)&opt_ignore_keyusage },
      "Ignore CMP signer cert key usage, else 'digitalSignature' must be allowed"},
    { "unprotected_errors", OPT_BOOL, {.bit = false}, { (const char **) &opt_unprotected_errors },
      "Accept missing or invalid protection of regular error messages and negative"},
    OPT_MORE("certificate responses (ip/cp/kup), revocation responses (rp), and PKIConf"),
    { "extracertsout", OPT_TXT, {.txt = NULL}, { &opt_extracertsout },
      "File to save extra certificates received in the extraCerts field"},
    { "extracerts_dir", OPT_TXT, {.txt = NULL}, { &opt_extracerts_dir },
      "Filepath to save extra certificates received in the extraCerts field"},
    { "extracerts_dir_format", OPT_TXT, {.txt = NULL}, { &opt_extracerts_dir_format },
      "Format to save extra certificates received in the extraCerts field"},
    { "cacertsout", OPT_TXT, {.txt = NULL}, { &opt_cacertsout },
      "File to save CA certificates received in the caPubs field of 'ip' messages"},
    { "cacerts_dir", OPT_TXT, {.txt = NULL}, { &opt_cacerts_dir },
      "Filepath to save CA certificates received in the caPubs field of 'ip' messages"},
    { "cacerts_dir_format", OPT_TXT, {.txt = NULL}, { &opt_cacerts_dir_format },
      "Format to save CA certificates received in the caPubs field of 'ip' messages"},

    OPT_HEADER("Client authentication"),
    { "ref", OPT_TXT, {.txt = NULL}, { &opt_ref },
      "Reference value to use as senderKID in case no -cert is given"},
    { "secret", OPT_TXT, {.txt = NULL}, { &opt_secret },
      "Secret value for authentication with a pre-shared key (PBM). Prepend 'pass:'"},
    { "cert", OPT_TXT, {.txt = NULL}, { &opt_cert },
      "Client cert (plus any extra one), needed unless using -secret for PBM."},
    OPT_MORE("This also used as default reference for subject DN and SANs."),
    OPT_MORE("Any further certs included are appended to the untrusted certs"),
    { "own_trusted", OPT_TXT, {.txt = NULL},  { &opt_own_trusted },
      "Optional certs to verify chain building for own CMP signer cert"},
    { "key", OPT_TXT, {.txt = NULL}, { &opt_key },
      "Key for the client certificate"},
    { "keypass", OPT_TXT, {.txt = NULL}, { &opt_keypass },
      "Password for the client's key"},
    { "digest", OPT_TXT, {.txt = NULL}, { &opt_digest },
      "Digest alg to use in msg protection and POPO signatures. Default \"sha256\""},
    { "mac", OPT_TXT, {.txt = NULL}, { &opt_mac},
      "MAC algorithm to use in PBM-based message protection. Default \"hmac-sha1\""},
    { "extracerts", OPT_TXT, {.txt = NULL}, { &opt_extracerts },
      "File(s) with certificates to append in extraCerts field of outgoing messages."},
    OPT_MORE("This can be used as the default CMP signer cert chain to include"),
    { "unprotected_requests", OPT_BOOL, {.bit = false}, { (const char **) &opt_unprotected_requests },
      "Send messages without CMP-level protection"},

    OPT_HEADER("Generic message"),
    { "cmd", OPT_TXT, {.txt = NULL}, { &opt_cmd },
      "CMP request to send: ir/cr/p10cr/kur/rr. Overrides 'use_case' if given"}, /* TODO? add genm */
    { "infotype", OPT_TXT, {.txt = NULL}, { &opt_infotype },
      "InfoType name for requesting specific info in genm, currently ignored"},
    { "geninfo", OPT_TXT, {.txt = NULL}, { &opt_geninfo },
      "generalInfo to place in request PKIHeader with type and integer value"},
    OPT_MORE("given in the form <OID>:int:<n>, e.g. \"1.2.3:int:987\""),

    OPT_HEADER("Certificate enrollment"),
    { "newkeytype", OPT_TXT, {.txt = NULL}, { &opt_newkeytype },
      "Generate key for ir/cr/kur of given type, e.g., EC:secp256r1 or RSA-2048"},
    { "newkey", OPT_TXT, {.txt = NULL}, { &opt_newkey },
      "Key to use for ir/cr/kur (defaulting to -key) if no -newkeytype is given."},
    OPT_MORE("File to save new generated key if -newkeytype is given"),
    { "newkeypass", OPT_TXT, {.txt = NULL}, { &opt_newkeypass },
      "Password for the file given for -newkey"},
    { "subject", OPT_TXT, {.txt = NULL}, { &opt_subject },
      "Distinguished Name (DN) of subject to use in the requested cert template"},
    { "issuer", OPT_TXT, {.txt = NULL}, { &opt_issuer },
      "DN of the issuer to place in the requested certificate template"},
    { "days", OPT_NUM, {.num = 0}, { (const char **) &opt_days },
      "Requested validity time of new cert in number of days"},
    { "reqexts", OPT_TXT, {.txt = NULL}, { &opt_reqexts },
      "Name of config file section defining certificate request extensions"},
    { "sans", OPT_TXT, {.txt = NULL}, { (const char **) &opt_sans },
      "Subject Alt Names (IPADDR/DNS/URI) to add as (critical) cert req extension"},
    { "san_nodefault", OPT_BOOL, {.bit = false}, { (const char **) &opt_san_nodefault},
      "Do not take default SANs from reference certificate (see -oldcert)"},
    { "policies", OPT_TXT, {.txt = NULL}, { &opt_policies},
      "Name of config file section defining policies request extension"},
    { "policy_oids", OPT_TXT, {.txt = NULL}, { (const char **) &opt_policy_oids},
      "Policy OID(s) to add as certificate policies request extension"},
    { "policy_oids_critical", OPT_BOOL, {.bit = false}, { (const char **) &opt_policy_oids_critical},
      "Flag the policy OID(s) given with -policies_ as critical"},
    { "popo", OPT_NUM, {.num = OSSL_CRMF_POPO_NONE - 1}, { (const char **) &opt_popo },
      "Proof-of-Possession (POPO) method to use for ir/cr/kur where"},
    OPT_MORE("-1 = NONE, 0 = RAVERIFIED, 1 = SIGNATURE (default), 2 = KEYENC"),
    { "csr", OPT_TXT, {.txt = NULL}, { &opt_csr },
      "CSR file in PKCS#10 format to use in p10cr for legacy support"},
    { "out_trusted", OPT_TXT, {.txt = NULL}, { &opt_out_trusted },
      "Certs to trust when verifying newly enrolled certs; defaults to -srvcert"},
    { "implicit_confirm", OPT_BOOL, {.bit = false}, { (const char **) &opt_implicit_confirm },
      "Request implicit confirmation of newly enrolled certificates"},
    { "disable_confirm", OPT_BOOL, {.bit = false}, { (const char **) &opt_disable_confirm },
      "Do not confirm newly enrolled certificates w/o requesting implicit confirm"},
    { "certout", OPT_TXT, {.txt = NULL}, { &opt_certout },
      "File to save newly enrolled certificate, possibly with chain and key"},
    { "chainout", OPT_TXT, {.txt = NULL}, { &opt_certout },
      "File to save the chain of the newly enrolled certificate"},

    OPT_HEADER("Certificate enrollment and revocation"),
    { "oldcert", OPT_TXT, {.txt = NULL}, { &opt_oldcert },
      "Certificate to be updated (defaulting to -cert) or to be revoked in rr;"},
    OPT_MORE("Its issuer is used as recipient unless -srvcert, -recipient or -issuer given"),
    { "revreason", OPT_NUM, {.num = CRL_REASON_NONE}, { (const char **) &opt_revreason },
      "Reason code to include in revocation request (RR)."},
    OPT_MORE("Values: 0..6, 8..10 (see RFC5280, 5.3.1) or -1. Default -1 = none included"),

    /* TODO? OPT_HEADER("Credentials format"), */
    /* TODO add opt_engine */

    OPT_HEADER("TLS connection"),
    { "tls_used", OPT_BOOL, {.bit = false}, { (const char **) &opt_tls_used },
      "Enable using TLS (also when other TLS options are not set)"},
    { "tls_cert", OPT_TXT, {.txt = NULL}, { &opt_tls_cert },
      "Client certificate (plus any extra certs) for TLS connection"},
    { "tls_key", OPT_TXT, {.txt = NULL}, { &opt_tls_key },
      "Client private key for TLS connection"},
    { "tls_keypass", OPT_TXT, {.txt = NULL}, { &opt_tls_keypass },
      "Client key password for TLS connection"},
    { "tls_extra", OPT_TXT, {.txt = NULL}, { &opt_tls_extra },
      "Extra certificates to provide to TLS server during TLS handshake"},
    { "tls_trusted", OPT_TXT, {.txt = NULL}, { &opt_tls_trusted },
      "File(s) with certs to trust for TLS server verification (TLS trust anchor)"},
    { "tls_host", OPT_TXT, {.txt = NULL}, { &opt_tls_host },
      "Address (rather than -server) to be checked during TLS host name validation"},

    OPT_HEADER("Debugging"),
    {"reqin", OPT_TXT, {.txt = NULL}, { (const char **) &opt_reqin},
     "Take sequence of CMP requests from file(s)"},
    {"reqout", OPT_TXT, {.txt = NULL}, { (const char **) &opt_reqout},
     "Save sequence of CMP requests to file(s)"},
    {"rspin", OPT_TXT, {.txt = NULL}, { (const char **) &opt_rspin},
     "Process sequence of CMP responses provided in file(s), skipping server"},
    {"rspout", OPT_TXT, {.txt = NULL}, { (const char **) &opt_rspout},
     "Save sequence of CMP responses to file(s)"},

    OPT_HEADER("CMP and TLS certificate status checking"),
    /* TODO extend verification options and align with cmpossl/apps/cmp.c */
    { "check_all", OPT_BOOL, {.bit = false}, { (const char **) &opt_check_all},
      "Check status not only for leaf certs but for all certs (except root)"},
    { "check_any", OPT_BOOL, {.bit = false}, { (const char **) &opt_check_any},
      "Check status for those certs (except root) that contain a CDP or AIA entry"},
    { "crls", OPT_TXT, {.txt = NULL}, {&opt_crls},
      "Enable CRL-based status checking and first use CRLs from given file/URL(s)"},
    { "use_cdp", OPT_BOOL, {.bit = false}, { (const char **) &opt_use_cdp },
      "Enable CRL-based status checking and enable using any CDP entries in certs"},
    { "cdps", OPT_TXT, {.txt = NULL}, {&opt_cdps},
      "Enable CRL-based status checking and use given URL(s) as fallback CDP"},
    { "crls_timeout", OPT_NUM, {.num = -1}, { (const char **)&opt_crls_timeout },
      "Timeout for CRL fetching, or 0 for none, -1 for default: 10 seconds"},
    { "crl_maxdownload_size", OPT_NUM, {.num = 0}, { (const char **)&opt_crl_maxdownload_size},
      "Maximum size of a CRL to be downloaded. Default: 0 = OpenSSL default = 100 kiB"},
    { "use_aia", OPT_BOOL, {.bit = false}, { (const char **) &opt_use_aia },
      "Enable OCSP-based status checking and enable using any AIA entries in certs"},
    { "ocsp", OPT_TXT, {.txt = NULL}, {&opt_ocsp},
      "Enable OCSP-based status checking and use given OCSP responder(s) as fallback"},
    { "ocsp_timeout", OPT_NUM, {.num = -1}, { (const char **)&opt_ocsp_timeout },
      "Timeout for getting OCSP responses, or 0 for none, -1 for default: 10 seconds"},
    { "ocsp_last", OPT_BOOL, {.bit = false}, { (const char **) &opt_ocsp_last },
      "Do OCSP-based status checks last (else before using CRLs downloaded from CDPs)"},
    { "stapling", OPT_BOOL, {.bit = false}, { (const char **) &opt_stapling },
      "Enable OCSP stapling for TLS; is tried before any other cert status checks"},

    OPT_V_OPTIONS, /* excludes "crl_check" and "crl_check_all" */

    OPT_END
};


static int SSL_CTX_add_extra_chain_free(SSL_CTX *ssl_ctx, STACK_OF(X509) *certs)
{
    int i;
    int res = 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        if (res != 0)
            res = SSL_CTX_add_extra_chain_cert(ssl_ctx,
                                               sk_X509_value(certs, i)) != 0;
    }
    sk_X509_free(certs); /* must not free the stack elements */
    if (res == 0)
        LOG_err("Unable to use TLS extra certs");
    return res;
}

static int set_gennames(OSSL_CMP_CTX *ctx, char *names, const char *desc)
{
    char *next;

    for (; names != NULL; names = next) {
        GENERAL_NAME *n;
        next = UTIL_next_item(names);

        if (strcmp(names, "critical") == 0) {
            (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL, 1);
            continue;
        }

        /* try IP address first, then URI or domain name */
        (void)ERR_set_mark();
        n = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_IPADD, names, 0);
        if (n == NULL)
            n = a2i_GENERAL_NAME(NULL, NULL, NULL,
                                 strchr(names, ':') != NULL ? GEN_URI : GEN_DNS,
                                 names, 0);
        (void)ERR_pop_to_mark();

        if (n == NULL) {
            LOG(FL_ERR, "bad syntax of %s '%s'", desc, names);
            return 0;
        }
        if (!OSSL_CMP_CTX_push1_subjectAltName(ctx, n)) {
            GENERAL_NAME_free(n);
            LOG_err("Out of memory");
            return 0;
        }
        GENERAL_NAME_free(n);
    }
    return 1;
}

#if 0
static X509_CRL *test_load_crl_cb(OPTIONAL void *arg, const char *url, int timeout,
                                  OPTIONAL const X509 *cert, OPTIONAL const char *desc)
{
    LOG(FL_DEBUG, "%s with url=%s\ndesc='%s'\n", (char *)arg, url, desc);
    if (url != NULL)
        return CONN_load_crl_http(url, timeout, desc);
    LOG_cert(FL_DEBUG, "could have used information from", cert);
    return NULL;
}
#endif

SSL_CTX *setup_TLS(STACK_OF(X509) *untrusted_certs)
{
#ifdef SEC_NO_TLS
    LOG_err("TLS is not enabled in this build");
    return NULL;
#else
    CREDENTIALS *tls_creds = NULL;
    SSL_CTX *tls = NULL;

    X509_STORE *tls_truststore = NULL;
    if (opt_tls_trusted != NULL) {
        tls_truststore = STORE_load(opt_tls_trusted, "trusted certs for TLS level");
        if (tls_truststore == NULL)
            goto err;
        if (!STORE_set_parameters(tls_truststore, vpm,
                                  opt_check_all, opt_stapling, crls,
                                  opt_use_cdp, opt_cdps, (int)opt_crls_timeout,
                                  opt_use_aia, opt_ocsp, (int)opt_ocsp_timeout))
            goto err;
        if (!STORE_set_crl_callback(tls_truststore, CRLMGMT_load_crl_cb, cmdat_tls))
            goto err;
    } else {
        LOG_warn("-tls_used given without -tls_trusted; will not authenticate the server");
    }

    if ((opt_tls_cert == NULL) != (opt_tls_key == NULL)) {
        LOG_err("Must give both -tls_cert and -tls_key options or neither");
        goto err;
    }
    if (opt_tls_key != NULL) {
        tls_creds = CREDENTIALS_load(opt_tls_cert, opt_tls_key, opt_tls_keypass,
                                     "credentials for TLS level");
        if (tls_creds == NULL)
            goto err;
    } else {
        LOG_warn("-tls_used given without -tls_key; cannot authenticate to the server");
    }
    static const char *tls_ciphers = NULL; /* or, e.g., "HIGH:!ADH:!LOW:!EXP:!MD5:@STRENGTH"; */
    const int security_level = -1;
    tls = TLS_new(tls_truststore, untrusted_certs, tls_creds, tls_ciphers, security_level);
    if (tls == NULL)
        goto err;

    /* if we did this before TLS_new() the expected host name while checking own TLS cert would be wrong */
    if (tls_truststore != NULL) {
        const char *host = opt_tls_host != NULL ? opt_tls_host : opt_server;
        if (!STORE_set1_host_ip(tls_truststore, host, host))
            goto err;
    }

    /* If present we append to the list also the certs from opt_tls_extra */
    if (opt_tls_extra != NULL) {
        STACK_OF(X509) *tls_extra = CERTS_load(opt_tls_extra, "extra certificates for TLS");
        if (tls_extra == NULL ||
            !SSL_CTX_add_extra_chain_free(tls, tls_extra)) {
            SSL_CTX_free(tls);
            tls = NULL;
            goto err;
        }
    }

 err:
    STORE_free(tls_truststore);
    CREDENTIALS_free(tls_creds);
    return tls;
#endif
}

X509_STORE *setup_CMP_truststore(void)
{
    X509_STORE *cmp_truststore = NULL;

    const char *trusted_cert_files = opt_trusted;
    cmp_truststore = STORE_load(trusted_cert_files, "trusted certs for CMP level");
    if (cmp_truststore == NULL)
        goto err;
    if (!STORE_set_parameters(cmp_truststore, vpm,
                              opt_check_all, false /* stapling */, crls,
                              opt_use_cdp, opt_cdps, (int)opt_crls_timeout,
                              opt_use_aia, opt_ocsp, (int)opt_ocsp_timeout) ||
        !STORE_set_crl_callback(cmp_truststore, CRLMGMT_load_crl_cb, cmdat_tls) ||
        /* clear any expected host/ip/email address; opt_expect_sender is used instead: */
        !STORE_set1_host_ip(cmp_truststore, NULL, NULL)) {
        STORE_free(cmp_truststore);
        cmp_truststore = NULL;
    }

 err:
    return cmp_truststore;
}

X509_EXTENSIONS *setup_X509_extensions(CMP_CTX *ctx)
{
    X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();
    X509V3_CTX ext_ctx;

    if (exts == NULL)
        return NULL;
    if (opt_reqexts != NULL || opt_policies != NULL) {
        X509V3_set_ctx(&ext_ctx, NULL, NULL, NULL, NULL, 0);
        X509V3_set_nconf(&ext_ctx, config);
    }

    if (opt_reqexts != NULL) {
        if (!X509V3_EXT_add_nconf_sk(config, &ext_ctx, opt_reqexts, &exts)) {
            LOG(FL_ERR, "cannot load extension section '%s'", opt_reqexts);
            goto err;
        }
    }

    if (opt_policies != NULL) {
        if (!X509V3_EXT_add_nconf_sk(config, &ext_ctx, opt_policies, &exts)) {
            LOG(FL_ERR, "cannot load policy section '%s'", opt_policies);
            goto err;
        }
    }

    if (opt_policies != NULL && opt_policy_oids != NULL) {
        LOG_err("Cannot have policies both via -policies and via -policy_oids");
        goto err;
    }

    if (opt_policy_oids_critical) {
        if (opt_policy_oids == NULL)
            LOG_warn("-policy_oids_critical has no effect unless -policy_oids is given");
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_POLICIES_CRITICAL, 1)) {
            LOG_err("Failed to set 'setPoliciesCritical' field of CMP context");
            goto err;
        }
    }

    while (opt_policy_oids != NULL) {
        ASN1_OBJECT *policy;
        POLICYINFO *pinfo;
        char *next = UTIL_next_item(opt_policy_oids);

        if ((policy = OBJ_txt2obj(opt_policy_oids, 1)) == NULL) {
            LOG(FL_ERR, "unknown policy OID '%s'", opt_policy_oids);
            goto err;
        }

        if ((pinfo = POLICYINFO_new()) == NULL) {
            LOG_err("Out of memory");
            ASN1_OBJECT_free(policy);
            goto err;
        }
        pinfo->policyid = policy;

        if (!OSSL_CMP_CTX_push0_policy(ctx, pinfo)) {
            LOG(FL_ERR, "cannot add policy with OID '%s'", opt_policy_oids);
            POLICYINFO_free(pinfo);
            goto err;
        }
        opt_policy_oids = next;
    }

    return exts;

 err:
    EXTENSIONS_free(exts);
    return NULL;
}

/* write OSSL_CMP_MSG DER-encoded to the specified file name item */
static int write_PKIMESSAGE(const OSSL_CMP_MSG *msg, char **filenames)
{
    char *file;

    if (msg == NULL || filenames == NULL) {
        LOG_err("NULL arg to write_PKIMESSAGE");
        return 0;
    }
    if (*filenames == NULL) {
        LOG_err("Not enough file names provided for writing PKIMessage");
        return 0;
    }

    file = *filenames;
    *filenames = UTIL_next_item(file);
    if (OSSL_CMP_MSG_write(file, msg) < 0) {
        LOG(FL_ERR, "Cannot write PKIMessage to file '%s'", file);
        return 0;
    }
    return 1;
}

/* read DER-encoded OSSL_CMP_MSG from the specified file name item */
static OSSL_CMP_MSG *read_PKIMESSAGE(char **filenames)
{
    char *file;
    OSSL_CMP_MSG *ret;

    if (filenames == NULL) {
        LOG_err("NULL arg to read_PKIMESSAGE");
        return NULL;
    }
    if (*filenames == NULL) {
        LOG_err("Not enough file names provided for reading PKIMessage");
        return NULL;
    }

    file = *filenames;
    *filenames = UTIL_next_item(file);

    ret = OSSL_CMP_MSG_read(file);
    if (ret == NULL)
        LOG(FL_ERR, "Cannot read PKIMessage from file '%s'", file);
    return ret;
}

/*-
 * Sends the PKIMessage req and on success place the response in *res
 * basically like OSSL_CMP_MSG_http_perform(), but in addition allows
 * to dump the sequence of requests and responses to files and/or
 * to take the sequence of requests and responses from files.
 */
static OSSL_CMP_MSG *read_write_req_resp(OSSL_CMP_CTX *ctx,
                                         const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *req_new = NULL;
    OSSL_CMP_MSG *res = NULL;
    OSSL_CMP_PKIHEADER *hdr;

    if (req != NULL && opt_reqout != NULL
            && !write_PKIMESSAGE(req, &opt_reqout))
        goto err;
    if (opt_reqin != NULL && opt_rspin == NULL) {
        if ((req_new = read_PKIMESSAGE(&opt_reqin)) == NULL)
            goto err;
#if 0
        /*-
         * The transaction ID in req_new read from opt_reqin may not be fresh.
         * In this case the server may complain "Transaction id already in use."
         * The following workaround unfortunately requires re-protection.
         */
        if (opt_reqin_new_tid
                && !OSSL_CMP_MSG_update_transactionID(ctx, req_new))
            goto err;
#endif
    }

    if (opt_rspin != NULL) {
        res = read_PKIMESSAGE(&opt_rspin);
    } else {
        const OSSL_CMP_MSG *actual_req = opt_reqin != NULL ? req_new : req;

        res =
#if 0
            opt_use_mock_srv ? OSSL_CMP_CTX_server_perform(ctx, actual_req) :
#endif
            OSSL_CMP_MSG_http_perform(ctx, actual_req);
    }
    if (res == NULL)
        goto err;

    if (opt_reqin != NULL || opt_rspin != NULL) {
        /* need to satisfy nonce and transactionID checks */
        ASN1_OCTET_STRING *nonce;
        ASN1_OCTET_STRING *tid;

        hdr = OSSL_CMP_MSG_get0_header(res);
        nonce = OSSL_CMP_HDR_get0_recipNonce(hdr);
        tid = OSSL_CMP_HDR_get0_transactionID(hdr);
        if (!OSSL_CMP_CTX_set1_senderNonce(ctx, nonce)
                || !OSSL_CMP_CTX_set1_transactionID(ctx, tid)) {
            OSSL_CMP_MSG_free(res);
            res = NULL;
            goto err;
        }
    }

    if (opt_rspout != NULL && !write_PKIMESSAGE(res, &opt_rspout)) {
        OSSL_CMP_MSG_free(res);
        res = NULL;
    }

 err:
    OSSL_CMP_MSG_free(req_new);
    return res;
}

static int set_name(const char *str,
                    int (*set_fn) (OSSL_CMP_CTX *ctx, const X509_NAME *name),
                    OSSL_CMP_CTX *ctx, const char *desc)
{
    if (str != NULL) {
        X509_NAME *n = UTIL_parse_name(str, MBSTRING_ASC, false);
        if (n == NULL) {
            LOG(FL_ERR, "cannot parse %s DN '%s'", desc, str);
            return 4;
        }
        if (!(*set_fn) (ctx, n)) {
            X509_NAME_free(n);
            LOG_err("Out of memory");
            return 5;
        }
        X509_NAME_free(n);
    }
    return CMP_OK;
}

int setup_cert_template(CMP_CTX *ctx)
{
    int err;

    err = set_name(opt_issuer, OSSL_CMP_CTX_set1_issuer, ctx, "issuer");
    if (err != CMP_OK)
        goto err;

    if (opt_san_nodefault) {
        if (opt_sans != NULL)
            LOG_warn("-san_nodefault has no effect when -sans is used");
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT, 1)) {
            LOG_err("Failed to set 'SubjectAltName_nodefault' field of CMP context");
            goto err;
        }
    }

    if (!set_gennames(ctx, opt_sans, "Subject Alternative Name")) {
        LOG_err("Failed to set 'Subject Alternative Name' of CMP context");
        err = 10;
        goto err;
    }

 err:
    return err;
}


static int handle_opt_geninfo(OSSL_CMP_CTX *ctx)
{
    long value;
    ASN1_OBJECT *type;
    ASN1_INTEGER *aint;
    ASN1_TYPE *val;
    OSSL_CMP_ITAV *itav;
    char *endstr;
    char *valptr = strchr(opt_geninfo, ':');

    if (valptr == NULL) {
        LOG_err("Missing ':' in -geninfo option");
        return CMP_R_INVALID_ARGS;
    }
    valptr[0] = '\0';
    valptr++;

    if (strncmp(valptr, "int:", 4) != 0) {
        LOG_err("Missing 'int:' in -geninfo option");
        return CMP_R_INVALID_ARGS;
    }
    valptr += 4;

    value = strtol(valptr, &endstr, 10);
    if (endstr == valptr || *endstr != '\0') {
        LOG_err("Cannot parse int in -geninfo option");
        return CMP_R_INVALID_ARGS;
    }

    type = OBJ_txt2obj(opt_geninfo, 1);
    if (type == NULL) {
        LOG_err("Cannot parse OID in -geninfo option");
        return CMP_R_INVALID_ARGS;
    }

    if ((aint = ASN1_INTEGER_new()) == NULL) {
        LOG_err("Out of memory");
        goto oom;
    }

    val = ASN1_TYPE_new();
    if (!ASN1_INTEGER_set(aint, value) || val == NULL) {
        LOG_err("Cannot set ASN1 integer or create new ASN1 type");
        ASN1_INTEGER_free(aint);
        goto oom;
    }
    ASN1_TYPE_set(val, V_ASN1_INTEGER, aint);
    itav = OSSL_CMP_ITAV_gen(type, val);
    if (itav == NULL) {
        LOG_err("Unable to create 'OSSL_CMP_ITAV' structure");
        ASN1_TYPE_free(val);
        goto oom;
    }

    if (!OSSL_CMP_CTX_push0_geninfo_ITAV(ctx, itav)) {
        LOG_err("Failed to add an ITAV for geninfo of the PKI message header");
        OSSL_CMP_ITAV_free(itav);
        return 14;
    }
    return CMP_OK;

 oom:
    ASN1_OBJECT_free(type);
    return 11; /* return values 12 and 13 unused */
}

int setup_ctx(CMP_CTX *ctx)
{
    CMP_err err = set_name(opt_expect_sender, OSSL_CMP_CTX_set1_expected_sender,
                           ctx, "expected sender");
    if (err != CMP_OK)
        return err;

    err = CMP_R_INVALID_ARGS;
    if (opt_extracerts != NULL) {
        STACK_OF(X509) *certs = CERTS_load(opt_extracerts, "extra certificates for CMP");
        if (certs == NULL) {
            LOG(FL_ERR, "Unable to load '%s' extra certificates for CMP", opt_extracerts);
            err = 8;
            goto err;
        } else {
            if (!OSSL_CMP_CTX_set1_extraCertsOut(ctx, certs)) {
                LOG_err("Failed to set 'extraCerts' field of CMP context");
                CERTS_free(certs);
                err = 9;
                goto err;
            }
            CERTS_free(certs);
        }
    }

    if (opt_popo < OSSL_CRMF_POPO_NONE - 1 || opt_popo > OSSL_CRMF_POPO_KEYENC) {
        LOG(FL_ERR, "Invalid value '%d' for popo method (must be between -1 and 2)", opt_popo);
        err = 10;
        goto err;
    }

    if (opt_days < 0) {
        LOG(FL_ERR, "Invalid value '%d' for -days option (must be a positive number)", opt_days);
        err = 10;
        goto err;
    }
    /* set option flags directly via CMP API */
    if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_ERRORS, opt_unprotected_errors)
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IGNORE_KEYUSAGE, opt_ignore_keyusage)
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_VALIDITY_DAYS, (int)opt_days)
        || (opt_popo >= OSSL_CRMF_POPO_NONE
            && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_POPO_METHOD, (int)opt_popo))
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DISABLE_CONFIRM, opt_disable_confirm)
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_SEND, opt_unprotected_requests)) {
        LOG_err("Failed to set option flags of CMP context");
        goto err;
    }

    if (opt_geninfo != NULL && (err = handle_opt_geninfo(ctx)) != CMP_OK)
        goto err;
    err = CMP_OK;

 err:
    return err;
}

CMP_err prepare_CMP_client(CMP_CTX **pctx, enum use_case use_case, OPTIONAL LOG_cb_t log_fn)
{
    X509_STORE *own_truststore = NULL;
    X509_STORE *cmp_truststore = NULL;
    CREDENTIALS *cmp_creds = NULL;
    CMP_err err = 1;

    X509_STORE *new_cert_truststore = NULL;
    const char *new_cert_trusted = opt_out_trusted == NULL ? opt_srvcert : opt_out_trusted;
    if (new_cert_trusted != NULL) {
        LOG(FL_TRACE, "Using '%s' as trust store for verifying new cert", new_cert_trusted);
        new_cert_truststore = STORE_load(new_cert_trusted, "trusted certs for verifying new cert");
        if (new_cert_truststore == NULL)
            goto err;
        /* use separated flag for checking any cert, for new certificate store */
        /* any -verify_hostname, -verify_ip, and -verify_email apply here */
        /* no cert status/revocation checks done for newly enrolled cert */
        if (!STORE_set_parameters(new_cert_truststore, vpm,
                                  opt_check_all, false /* stapling */, crls,
                                  opt_use_cdp, opt_cdps, (int)opt_crls_timeout,
                                  opt_use_aia, opt_ocsp, (int)opt_ocsp_timeout))
            goto err;
        if (!STORE_set_crl_callback(new_cert_truststore, CRLMGMT_load_crl_cb, cmdat_new))
            goto err;
    }
    /* cannot set these vpm options before STORE_set_parameters(new_cert_truststore, ...) */
    if (opt_check_any)
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_STATUS_CHECK_ANY);
    if (opt_ocsp_last)
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_OCSP_LAST);

    if (opt_secret != NULL || opt_key != NULL) {
        const char *const creds_desc = "credentials for CMP level";
        if ((opt_secret != NULL && opt_ref != NULL)
            || (use_case != update && use_case != revocation && opt_secret != NULL)) {
            /* use PBM except for kur and rr if secret is present */
            char *secret = FILES_get_pass(opt_secret, "PBM-based message protection");
            cmp_creds = CREDENTIALS_new(NULL, NULL, NULL, secret, opt_ref);
            UTIL_cleanse_free(secret);
            if (opt_own_trusted != NULL)
                LOG_warn("-own_trusted option is ignored since -secret is used");
        } else {
            cmp_creds = CREDENTIALS_load(opt_cert, opt_key, opt_keypass, creds_desc);
            if (opt_own_trusted != NULL) {
                LOG(FL_TRACE, "Using '%s' as trust store for verifying own CMP signer cert", opt_own_trusted);
                own_truststore = STORE_load(opt_own_trusted, "trusted certs for verifying own CMP signer cert");
                err = 4;
                if (own_truststore == NULL)
                    goto err;
                err = 5;
                /* no cert status/revocation checks done for here */
                if (!STORE_set_parameters(own_truststore, NULL /* vpm */,
                                          false, false, NULL,
                                          false, NULL, -1,
                                          false, NULL, -1))
                    goto err;
            }
        }
        if (cmp_creds == NULL) {
            LOG(FL_ERR, "Unable to set up %s", creds_desc);
            goto err;
        }
    } else {
        if (opt_own_trusted != NULL)
            LOG_warn("-own_trusted option is ignored since -cert and -key are not used");
    }

    err = 2;
    if (opt_srvcert != NULL && opt_trusted != NULL)
        LOG_warn("-trusted option is ignored since -srvcert option is present");
    cmp_truststore = opt_trusted == NULL ? NULL : setup_CMP_truststore();
    STACK_OF(X509) *untrusted_certs = opt_untrusted == NULL ? NULL :
        CERTS_load(opt_untrusted, "untrusted certs for CMP");
    if ((cmp_truststore == NULL && opt_trusted != NULL)
            || (untrusted_certs == NULL && opt_untrusted != NULL))
        goto err;

    OSSL_CMP_transfer_cb_t transfer_fn = NULL; /* default HTTP(S) transfer */
    if (opt_reqin != NULL && opt_rspin != NULL)
        LOG_warn("-reqin is ignored since -rspin is present");
#if 0
    if (opt_reqin_new_tid && opt_reqin == NULL)
        LOG_warn("-reqin_new_tid is ignored since -reqin is not present");
#endif
    if (opt_reqin != NULL || opt_reqout != NULL
            || opt_rspin != NULL || opt_rspout != NULL)
        transfer_fn = read_write_req_resp;

    const bool implicit_confirm = opt_implicit_confirm;

    if ((int)opt_total_timeout < -1) {
        LOG_err("Only non-negative values allowed for -total_timeout");
        goto err;
    }
    err = CMPclient_prepare(pctx, log_fn,
                            cmp_truststore, opt_recipient,
                            untrusted_certs,
                            cmp_creds, own_truststore,
                            opt_digest, opt_mac,
                            transfer_fn, (int)opt_total_timeout,
                            new_cert_truststore, implicit_confirm);
    CERTS_free(untrusted_certs);
    STORE_free(new_cert_truststore);
    if (err != CMP_OK)
        goto err;

    if (opt_srvcert != NULL) {
        X509 *srvcert = CERT_load(opt_srvcert, NULL /* pass */, "directly trusted CMP server certificate");
        if (srvcert == NULL || !OSSL_CMP_CTX_set1_srvCert(*pctx, srvcert))
            err = 3;
        X509_free(srvcert);
    }

 err:
    CREDENTIALS_free(cmp_creds);
    STORE_free(cmp_truststore);
    STORE_free(own_truststore);
    return err;
}

static int reqExtensions_have_SAN(X509_EXTENSIONS *exts)
{
    if (exts == NULL)
        return 0;
    return X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1) >= 0;
}

int setup_transfer(CMP_CTX *ctx)
{
    CMP_err err;

    const char *path = opt_path;
    const char *server = opt_server;

    if ((int)opt_msg_timeout < -1) {
        LOG_err("Only non-negative values allowed for -msg_timeout");
        err = 16;
        goto err;
    }

    if (opt_tls_cert == NULL && opt_tls_key == NULL && opt_tls_keypass == NULL
          && opt_tls_extra == NULL && opt_tls_trusted == NULL
          && opt_tls_host == NULL && opt_tls_used == true) {
        LOG_warn("-tls_used will be ignored. No other tls options set");
        opt_tls_used = false;
    }

    SSL_CTX *tls = NULL;
    if (opt_tls_used && (tls = setup_TLS(OSSL_CMP_CTX_get0_untrusted_certs(ctx))) == NULL) {
        LOG_err("Unable to setup TLS for CMP client");
        err = 17;
        goto err;
    }

    err = CMPclient_setup_HTTP(ctx, server, path, (int)opt_msg_timeout,
                               tls, opt_proxy, opt_no_proxy);
#ifndef SEC_NO_TLS
    TLS_free(tls);
#endif
    if (err != CMP_OK) {
        LOG_err("Unable to setup HTTP for CMP client");
        goto err;
    }
 err:
    return err;
}

size_t get_cert_filename(
    X509            *cert,
    const char      *prefix,
    const char      *suffix,
    char            *name_utf8_buf,
    size_t          name_utf8_buf_len,
    unsigned long   flags)
{
    (void)flags;
    size_t len = safe_string_copy(prefix, name_utf8_buf, name_utf8_buf_len, NULL);

    char subject[256];
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, subject, sizeof(subject));
    len += safe_string_copy(subject, name_utf8_buf+len, name_utf8_buf_len-len, NULL);
    len += safe_string_copy(" [", name_utf8_buf+len, name_utf8_buf_len-len, NULL);

	unsigned char sha1[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    X509_digest(cert, EVP_sha1(), sha1, &size);
    len += bintohex(sha1, size, false, '-', 4, name_utf8_buf+len, name_utf8_buf_len-len, NULL);
    len += safe_string_copy("].", name_utf8_buf+len, name_utf8_buf_len-len, NULL);
    len += safe_string_copy(suffix, name_utf8_buf+len, name_utf8_buf_len-len, NULL);
    return len;
}

static int client_check_revocation_status(const char * certificate_path)
{
    LOG(FL_INFO, "start usecase: check_revocation_status");
    LOG(FL_INFO, "verify certificate in file  %s", certificate_path);
    LOG(FL_DEBUG, "trusted certs: %s", opt_tls_trusted);

    FILE *fp = fopen(certificate_path, "r");
    if (!fp) {
        LOG(FL_ERR, "unable to open input certfile: %s", certificate_path);
        return 1;
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        LOG(FL_ERR, "unable to parse certificate in: %s", certificate_path);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    /* cert this is a valid cert pointer from here on */
    LOG(FL_DEBUG, "certificate read successfully:");
    CDP_log_cert(FL_DEBUG, cert);

    LOG(FL_DEBUG, "create and init certificate truststore");
    X509_STORE *store = STORE_load(opt_tls_trusted, NULL);
    if (store == NULL)
        goto err;

    if (!STORE_set_parameters(store, vpm,
                                opt_check_all, opt_stapling, crls,
                                opt_use_cdp, opt_cdps, (int)opt_crls_timeout,
                                opt_use_aia, opt_ocsp, (int)opt_ocsp_timeout))
        goto err;

    if (!STORE_set_crl_callback(store, CRLMGMT_load_crl_cb, cmdat_tls))
        goto err;

    LOG(FL_DEBUG, "create and init store context");
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);

    LOG(FL_INFO, "start certificate verification now");
    int ret = X509_verify_cert(ctx);

    /* check for errors and clean up */
    if (ret > 0) {
        LOG(FL_INFO, "certificate verification finished successfully");
    }
    else {
        int err = X509_STORE_CTX_get_error(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        LOG(FL_ERR, "certificate verification failed: (%d) [%d] %s", depth,
            err, X509_verify_cert_error_string(err));
    }

err:
    /* done with store, context and x509 cert */
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    return 0;
}

static int CMPclient(enum use_case use_case, OPTIONAL LOG_cb_t log_fn)
{
    CMP_err err = 1;
    CMP_CTX *ctx = NULL;
    EVP_PKEY *new_pkey = NULL;
    X509_EXTENSIONS *exts = NULL;
    CREDENTIALS *new_creds = NULL;

    if ((opt_cacerts_dir_format != NULL && opt_cacerts_dir == NULL)
            || (opt_cacerts_dir_format == NULL && opt_cacerts_dir != NULL)) {
        LOG_warn("-cacerts_dir_format and -cacerts_dir has to be set both to store certs from caPubs");
        opt_cacerts_dir_format = NULL;
        opt_cacerts_dir = NULL;
    }

    if ((opt_extracerts_dir_format != NULL && opt_extracerts_dir == NULL)
            || (opt_extracerts_dir_format == NULL && opt_extracerts_dir != NULL)) {
        LOG_warn("-extracerts_dir_format and -extracerts_dir have both to be set to store certs from extracerts");
        opt_extracerts_dir_format = NULL;
        opt_extracerts_dir = NULL;
    }

    if (opt_infotype != NULL) {
        char id_buf[100] = "id-it-";

        strncat(id_buf, opt_infotype, sizeof(id_buf) - strlen(id_buf) - 1);
        if ((infotype = OBJ_sn2nid(id_buf)) == NID_undef) {
            LOG_err("Unknown OID name in -infotype option");
            goto err;
        }
        /* TODO remove warning when genm is supported */
        LOG_warn("-infotype option is ignored as long as 'genm' is not supported");
    }

    if (!opt_secret && ((opt_cert == NULL) != (opt_key == NULL))) {
        LOG_err("Must give both -cert and -key options or neither");
        goto err;
    }
    if (use_case == update) {
        if (opt_oldcert == NULL && opt_cert != NULL) {
            LOG(FL_INFO, "-oldcert is defaulting to -cert for 'kur' command");
            opt_oldcert = opt_cert;
        }
        if (opt_key == NULL && opt_keypass == NULL) {
            LOG(FL_INFO, "-newkey and -newkeypass are defaulting to -key and -keypass");
            opt_key = opt_newkey;
            opt_keypass = opt_newkeypass;
        }
    } else {
        if (opt_secret != NULL && opt_key != NULL)
            LOG_warn("-key value will not be used for signing messages since -secret option selects PBM-based protection");
    }
    if (!opt_unprotected_requests && opt_secret == NULL && opt_key == NULL) {
        LOG_err("Must give client credentials unless -unprotected_requests is set");
        goto err;
    }

    if (opt_ref == NULL && opt_cert == NULL && opt_subject == NULL) {
        /* ossl_cmp_hdr_init() takes sender name from cert or else subject */
        /* TODO maybe else take as sender default the subjectName of oldCert or p10cr */
        LOG_err("Must give -ref if no -cert and no -subject given");
        goto err;
    }

    if (opt_check_all && opt_check_any) {
        LOG_warn("-check_all overrides -check_any");
    }

    err = 21;
    if (use_case == pkcs10 && opt_csr == NULL) {
        LOG_err("-csr option is missing for command 'p10cr'");
        goto err;
    }
    if (use_case == revocation && opt_oldcert == NULL) {
        LOG_err("-oldcert option is missing for command 'rr' (revocation)");
        goto err;
    }

    if (opt_cacerts_dir_format != NULL && FILES_get_format(opt_cacerts_dir_format) == FORMAT_UNDEF) {
        err = 22;
        LOG_err("-cacerts_dir_format is not of type 'PEM', 'DER', or 'P12'/'PKCS12'");
        goto err;
    }

    if (opt_extracerts_dir_format != NULL && FILES_get_format(opt_extracerts_dir_format) == FORMAT_UNDEF) {
        err = 24;
        LOG_err("-extracerts_format is not of type 'PEM', 'DER', or 'P12'/'PKCS12'");
        goto err;
    }

    err = 30;
    bool crl_check = opt_crls != NULL || opt_use_cdp || opt_cdps != NULL;
    bool ocsp_check = opt_use_aia || opt_ocsp != NULL;
    if (opt_crls_timeout >= 0 && !opt_use_cdp && opt_cdps == NULL) {
        LOG_warn("Ignoring -crls_timeout since -use_cdp and -cdps options are not given");
    }
    if (opt_ocsp_timeout >= 0 && !ocsp_check) {
        LOG_warn("Ignoring -ocsp_timeout since -use_aia and -ocsp options are not given");
    }
    if ((crl_check || ocsp_check) && opt_trusted == NULL) {
        LOG_warn("Certificate status checks are enabled without providing the -trusted option");
    }
    if ((crl_check || ocsp_check || opt_stapling) && opt_tls_used && opt_tls_trusted == NULL) {
        LOG_warn("Cannot do TLS certificate status checks without -tls_trusted option");
    }
    if ((opt_check_all || opt_check_any) && !crl_check && !ocsp_check) {
        LOG_err("-check_all or -check_any is given without any option enabling use of CRLs or OCSP");
        goto err;
    }
    if (opt_ocsp_last && !ocsp_check) {
        LOG_err("-ocsp_last is given without -ocsp or -use_aia enabling OCSP-based cert status checking");
        goto err;
    }
    if (opt_stapling && !opt_tls_used) {
        LOG_warn("-stapling option is given without -tls_used");
    }
#ifdef OPENSSL_NO_OCSP
    if (ocsp_check || opt_stapling)
        LOG_warn("OCSP may be not supported by the OpenSSL build used by the SecUtils");
#endif
#if defined(OPENSSL_NO_OCSP) || OPENSSL_VERSION_NUMBER < 0x1010001fL
    if (opt_stapling)
        LOG_warn("OCSP stapling may be not supported by the OpenSSL build used by the SecUtils");
#endif
    err = 31;
    if (opt_crls != NULL) {
        crls = CRLs_load(opt_crls, (int)opt_crls_timeout, "pre-loaded CRLs");
        if (crls == NULL)
            goto err;
    }

    err = prepare_CMP_client(&ctx, use_case, log_fn);
    if (err != CMP_OK) {
        LOG_err("Failed to prepare CMP client");
        goto err;
    }

    if ((err = setup_ctx(ctx)) != CMP_OK) {
        LOG_err("Failed to prepare CMP client");
        goto err;
    }

    if (use_case == pkcs10 || use_case == revocation) {
        if (opt_newkeytype != 0)
            LOG_warn("-newkeytype option is ignored for 'p10cr' and 'rr' commands");
        if (opt_newkey != 0)
            LOG_warn("-newkey option is ignored for 'p10cr' and 'rr' commands");
        if (opt_days != 0)
            LOG_warn("-days option is ignored for 'p10cr' and 'rr' commands");
        if (opt_popo != OSSL_CRMF_POPO_NONE - 1)
            LOG_warn("-popo option is ignored for commands other than 'ir', 'cr', and 'p10cr'");
    } else {
        err = 18;
        if (opt_newkeytype != NULL) {
            if (opt_newkey == NULL) {
                LOG_err("Missing -newkey option specifying the file to save the new key");
                goto err;
            }
            const char *key_spec = strcmp(opt_newkeytype, "ECC") == 0 ? "EC:secp256r1" : opt_newkeytype;
            new_pkey = KEY_new(key_spec);
            if (new_pkey == NULL) {
                LOG(FL_ERR, "Unable to generate new private key according to specification '%s'",
                    key_spec);
                goto err;
            }
        } else {
            if (opt_newkey == NULL && opt_key == NULL) {
                LOG_err("Missing -newkeytype or -newkey or -key option");
                goto err;
            }
            if (opt_newkey != NULL) {
                new_pkey = KEY_load(opt_newkey, opt_newkeypass, NULL /* engine */,
                                                  "private key to use for certificate request");
                if (new_pkey == NULL) {
                    goto err;
                }
            }
        }
    }

    if (use_case == imprint || use_case == bootstrap || use_case == check_originality) {
        if (reqExtensions_have_SAN(exts) && opt_sans != NULL) {
            LOG_err("Cannot have Subject Alternative Names both via -reqexts and via -sans");
            err = CMP_R_MULTIPLE_SAN_SOURCES;
            goto err;
        }

        if ((err = setup_cert_template(ctx)) != CMP_OK)
            goto err;
        if ((exts = setup_X509_extensions(ctx)) == NULL) {
            LOG_err("Unable to set up X509 extensions for CMP client");
            err = 19;
            goto err;
        }
    } else {
        if (opt_subject != NULL) {
            if (opt_ref == NULL && opt_cert == NULL) {
                /* use subject as default sender unless oldcert subject is used */
                err = set_name(opt_subject, OSSL_CMP_CTX_set1_subjectName, ctx, "subject");
                if (err != CMP_OK)
                    goto err;
            } else {
                LOG_warn("-subject option is ignored for commands other than 'ir' and 'cr'");
            }
        }
        if (opt_issuer != NULL)
            LOG_warn("-issuer option is ignored for commands other than 'ir' and 'cr'");
        if (opt_reqexts != NULL)
            LOG_warn("-reqexts option is ignored for commands other than 'ir' and 'cr'");
        if (opt_san_nodefault)
            LOG_warn("-san_nodefault option is ignored for commands other than 'ir' and 'cr'");
        if (opt_sans != NULL)
            LOG_warn("-sans option is ignored for commands other than 'ir' and 'cr'");
        if (opt_policies != NULL)
            LOG_warn("-policies option is ignored for commands other than 'ir' and 'cr'");
        if (opt_policy_oids != NULL)
            LOG_warn("-policy_oids option is ignored for commands other than 'ir' and 'cr'");
    }

// TODO handle check_revocation_status option conflicts
    if (use_case != pkcs10 && opt_csr != NULL)
        LOG_warn("-csr option is ignored for commands other than 'p10cr'");
    if (use_case != update && use_case != revocation && opt_oldcert != NULL)
        LOG_warn("-oldcert option used only as reference cert for commands other than 'kur' and 'rr'");
    if (use_case == revocation) {
        if (opt_implicit_confirm)
            LOG_warn("-implicit_confirm option is ignored for 'rr' commands");
        if (opt_disable_confirm)
            LOG_warn("-disable_confirm option is ignored for 'rr' commands");
        if (opt_certout != NULL)
            LOG_warn("-certout option is ignored for 'rr' commands");
        if (opt_chainout != NULL)
            LOG_warn("-chainout option is ignored for 'rr' commands");
    } else {
        if (opt_revreason != CRL_REASON_NONE)
            LOG_warn("-revreason option given for commands other than 'rr'");
    }

    if (opt_tls_cert != NULL || opt_tls_key != NULL || opt_tls_keypass != NULL
        || opt_tls_extra != NULL || opt_tls_trusted != NULL
        || opt_tls_host != NULL)
        if (!opt_tls_used)
            LOG_warn("TLS options(s) are ignored since -tls_used is not given");
    if ((err = setup_transfer(ctx)) != CMP_OK)
        goto err;

    X509 *oldcert = NULL;
    if (opt_oldcert != NULL) {
        oldcert = CERT_load(opt_oldcert, opt_keypass,
                            use_case == update ? "certificate to be updated" :
                            use_case == revocation ? "certificate to be revoked" :
                            "reference certificate (oldcert)");
        err = 19;
        if (oldcert == NULL || !OSSL_CMP_CTX_set1_oldCert(ctx, oldcert))
        goto err;
    }

    if ((int)opt_revreason < CRL_REASON_NONE
        || (int)opt_revreason > CRL_REASON_AA_COMPROMISE
        || (int)opt_revreason == 7) {
        LOG_err("Invalid revreason given. Valid values are -1..6, 8..10");
        err = 20;
        goto err;
    }

    switch (use_case) {
    case imprint:
        err = CMPclient_imprint(ctx, &new_creds, new_pkey, opt_subject, exts);
        break;
    case check_originality:
    case bootstrap:
        err = CMPclient_bootstrap(ctx, &new_creds, new_pkey, opt_subject, exts);
        break;
    case pkcs10:
        {
            X509_REQ *csr = CSR_load(opt_csr, "PKCS#10 CSR for p10cr");
            if (csr == NULL) {
                err = 15;
                goto err;
            }
            err = CMPclient_pkcs10(ctx, &new_creds, csr);
            X509_REQ_free(csr);
        }
        break;
    case update:
        if (opt_oldcert == NULL)
            err = CMPclient_update(ctx, &new_creds, new_pkey);
        else
            err = CMPclient_update_anycert(ctx, &new_creds, oldcert, new_pkey);
        break;
    case revocation:
        err = CMPclient_revoke(ctx, oldcert, (int)opt_revreason);
        /* SimpleLra does not accept CRL_REASON_NONE: "missing crlEntryDetails for REVOCATION_REQ" */
        break;
    case genm:
        /* TODO? implement genm and remove next 4 lines when done */
        LOG(FL_ERR, "CMP request type 'genm' is not supported");
        err = 22;
        if (strstr(opt_config, "test_config.cnf") != NULL)
            err = CMP_OK;
        break;
    default:
        LOG(FL_ERR, "Unknown use case '%d' used", use_case);
        err = 21;
    }
    X509_free(oldcert);
    if (err != CMP_OK) {
        LOG_err("Failed to perform CMP transaction");
        goto err;
    }

    if (opt_cacertsout != NULL) {
        STACK_OF(X509) *certs = OSSL_CMP_CTX_get1_caPubs(ctx);
        if (sk_X509_num(certs) > 0
                && CERTS_save(certs, opt_cacertsout, "CA") < 0) {
            LOG(FL_ERR, "Failed to store %s certs in '%s'", opt_cacertsout);
            CERTS_free(certs);
            err = 23;
            goto err;
        }
        CERTS_free(certs);
    }

    if (opt_cacerts_dir != NULL) {
        LOG_info("Extracting certs from caPubs:");
        STACK_OF(X509) *caPubs_certs = OSSL_CMP_CTX_get1_caPubs(ctx);
        if (sk_X509_num(caPubs_certs) == 0)
            LOG(FL_WARN, "No certificate was presented in caPubs to store under %s", opt_cacerts_dir);
        else if (sk_X509_num(caPubs_certs) > 1)
            LOG_err("More than 1 certificate was presented in caPubs so they are ignored");

        X509 *cert = sk_X509_value(caPubs_certs, 0);
        if (cert != NULL) {
            if (X509_check_issued(cert, cert) != 0) {
                LOG_err("Certificate in caPubs is not self signed and thus is not stored");
            }
            else {
                char cacert_path[FILENAME_MAX];
                get_cert_filename(cert, opt_cacerts_dir, opt_cacerts_dir_format, cacert_path, sizeof(cacert_path), 0);
                if (!FILES_store_cert(cert, cacert_path, FILES_get_format(opt_cacerts_dir_format), "CA")) {
                    LOG(FL_ERR, "Failed to store cert from caPubs under '%s'", opt_cacerts_dir);
                }
            }
            X509_free(cert);
        }
        sk_X509_pop_free(caPubs_certs, X509_free);
    }

    if (opt_extracertsout != NULL) {
        STACK_OF(X509) *certs = OSSL_CMP_CTX_get1_extraCertsIn(ctx);
        if (sk_X509_num(certs) > 0
                && CERTS_save(certs, opt_extracertsout, "extra") < 0) {
            LOG(FL_ERR, "Failed to store '%s'", opt_extracertsout);
            CERTS_free(certs);
            err = 25;
            goto err;
        }
        CERTS_free(certs);
    }

    if (opt_extracerts_dir != NULL) {
        LOG_info("Extracting certs from extracerts:");
        STACK_OF(X509) *extra_certs = OSSL_CMP_CTX_get1_extraCertsIn(ctx);
        if (sk_X509_num(extra_certs) <= 0) {
            LOG(FL_WARN, "No certificates were presented in extracerts to store under %s", opt_extracerts_dir);
        }
        else {
            LOG(FL_DEBUG, "%d certificates in extracerts given", sk_X509_num(extra_certs));
            int i;
            for (i = 0; i < sk_X509_num(extra_certs); ++i) {
                X509 *cert = sk_X509_value(extra_certs, i);
                if (X509_check_issued(cert, cert) == 0)
                    LOG(FL_WARN, "Certificate number %d in extracerts is self signed and thus is not stored", i);
                else {
                    char extracert_path[FILENAME_MAX];
                    get_cert_filename(cert, opt_extracerts_dir, opt_extracerts_dir_format, extracert_path, sizeof(extracert_path), 0);
                    if (!FILES_store_cert(cert, extracert_path, FILES_get_format(opt_extracerts_dir_format), "store extra cert")) {
                        LOG(FL_ERR, "Failed to store cert number %d from extracerts in dir '%s'", i, opt_extracerts_dir);
                    }
                }
                X509_free(cert);
            }
        }
        sk_X509_pop_free(extra_certs, X509_free);
    }

    if (use_case != revocation && use_case != genm && use_case != check_revocation_status) {
        if (use_case != pkcs10 && opt_newkey != NULL && opt_newkeytype != NULL) {
            if (opt_chainout != NULL)
                LOG_warn("-chainout option is ignored");

            const char *new_desc = "newly enrolled certificate and related chain and key";
            if (!CREDENTIALS_save(new_creds, opt_certout, opt_newkey, opt_newkeypass, new_desc)) {
                LOG_err("Failed to save newly enrolled credentials");
                err = 26;
                goto err;
            }
        } else {
            const char *new_desc = "newly enrolled certificate";
            X509 *cert = CREDENTIALS_get_cert(new_creds);
            STACK_OF(X509)* certs = CREDENTIALS_get_chain(new_creds);
            if (certs == NULL || opt_chainout != NULL) {
                if (!CERT_save(cert, opt_certout, new_desc)) {
                    err = 27;
                    goto err;
                }
                if (opt_chainout != NULL &&
                    CERTS_save(certs, opt_chainout, new_desc) < 0) {
                    err = 28;
                    goto err;
                }
            } else {
                if (sk_X509_unshift(certs, cert) == 0) { /* prepend cert */
                    LOG(FL_ERR, "Out of memory writing certs to file '%s'", opt_certout);
                    err = 29;
                    goto err;
                }
                if (CERTS_save(certs, opt_certout, new_desc) < 0) {
                    err = 30;
                    goto err;
                }
            }
        }
    }

 err:
    CMPclient_finish(ctx); /* this also frees ctx */
    KEY_free(new_pkey);
    EXTENSIONS_free(exts);
    CREDENTIALS_free(new_creds);
    CRLs_free(crls);

    LOG_close(); /* not really needed since done also in sec_deinit() */
    if (err != CMP_OK) {
        LOG(FL_ERR, "CMPclient error %d", err);
    }
    return err;
}

int print_help(const char *prog)
{
    BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_stdout, "Usage:\n"
               "%s (imprint | bootstrap | check_originality | update | revoke) [-section <CA>]\n"
               "%s options\n\n"
               "Available options are:\n",
               prog, prog);
    OPT_help(cmp_opts, bio_stdout);
    BIO_free(bio_stdout);
    return EXIT_SUCCESS;
}

bool set_verbosity(long level)
{
    if (level < LOG_EMERG || level > LOG_TRACE) {
        LOG(FL_ERR, "Logging verbosity level %d out of range (0 .. 8)", level);
        return false;
    }
    opt_verbosity = level;
    LOG_set_verbosity((severity)level);
    return true;
}

static int client_demo(enum use_case use_case)
{
    CMP_err err = CMP_OK;

    switch (use_case) {
    case check_revocation_status:
        client_check_revocation_status(opt_cert);
        break;
    default:
        LOG(FL_ERR, "Unknown use case '%d' used", use_case);
        err = 19;
    }
    if (err != CMP_OK) {
        LOG(FL_ERR, "CMPclient error %d\n", err);
    }
    return err;
}

int main(int argc, char *argv[])
{
    int i;
    int rv, rc = EXIT_FAILURE;

#if OPENSSL_VERSION_NUMBER >= 0x10100002L
# ifndef OPENSSL_NO_CRYPTO_MDEBUG
    char *p = getenv("OPENSSL_DEBUG_MEMORY");
    if (p != NULL && strcmp(p, "on") == 0)
        CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
# endif
#endif

    LOG_set_name("cmpClient");
    sec_ctx *sec_ctx = sec_init(); /* this also initializes logging to default */
    if (sec_ctx == NULL)
        goto end;

    LOG_cb_t log_fn = NULL;
    if (CMPclient_init(log_fn) != CMP_OK)
        goto end;

    enum use_case use_case = no_use_case; /* default */
    if (argc > 1) {
        if (strcmp(argv[1], "imprint") == 0) {
            use_case = imprint;
        } else if (strcmp(argv[1], "bootstrap") == 0) {
            use_case = bootstrap;
        } else if (strcmp(argv[1], "check_originality") == 0) {
            use_case = check_originality;
        } else if (strcmp(argv[1], "update") == 0) {
            use_case = update;
        } else if (strcmp(argv[1], "revoke") == 0) {
            use_case = revocation;
        } else if (strcmp(argv[1], "check_revocation_status") == 0) {
            use_case = check_revocation_status;
        }
    }

    if (!OPT_init(cmp_opts))
        goto end;
    /*
     * handle -help, -config, -section, and -verbosity upfront to take effect for other opts
     */
    const char *prog = argv[0];
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (argv[i][1] == '-')
                argv[i]++;
            if (strcmp(argv[i] + 1, "help") == 0) {
                return print_help(prog);
            } else if (i + 1 < argc) {
                if (strcmp(argv[i] + 1, "config") == 0)
                    opt_config = argv[++i];
                else if (strcmp(argv[i] + 1, "section") == 0)
                    opt_section = argv[++i];
                else if (strcmp(argv[i] + 1, "verbosity") == 0
                         && !set_verbosity(UTIL_atoint(argv[++i])))
                    goto end; /* INT_MIN on parse error */
            }
        }
    }
    if (opt_config[0] == '\0')
        opt_config = NULL;
    if (opt_section[0] == '\0')
        opt_section = DEFAULT_SECTION;

    if (use_case != no_use_case) {
        snprintf(demo_sections, sizeof(demo_sections), "%s,%s", opt_section, argv[1]);
        opt_section = demo_sections;
    }

    if (opt_config != NULL) {
        LOG(FL_INFO, "Using section(s) '%s' of CMP configuration file '%s'",
            opt_section, opt_config);
        if ((config = CONF_load_options(NULL, opt_config, opt_section, cmp_opts)) == NULL)
            goto end;
    }
    vpm = X509_VERIFY_PARAM_new();
    if (vpm == 0) {
        LOG_err("Out of memory");
        goto end;
    }
    cmdat_tls = CRLMGMT_DATA_new();
    if (cmdat_tls == 0) {
        LOG_err("Out of memory");
        goto end;
    }
    cmdat_new = CRLMGMT_DATA_new();
    if (cmdat_new == 0) {
        LOG_err("Out of memory");
        goto end;
    }
    if (config != NULL && !CONF_update_vpm(config, opt_section, vpm))
        goto end;
    argv++;
    if (use_case != no_use_case)
        argv++; /* skip first option since use_case is given */
    rv = OPT_read(cmp_opts, argv, vpm);
    if (rv == -1) /* can only happen for ---help since [-]-help has already been handled */
        return print_help(prog);
    if (rv <= 0)
        goto end;
    if (!set_verbosity(opt_verbosity))
        goto end;

    CRLMGMT_DATA_set_proxy_url(cmdat_tls, opt_cdp_proxy);
    CRLMGMT_DATA_set_crl_max_download_size(cmdat_tls, opt_crl_maxdownload_size);
    CRLMGMT_DATA_set_crl_cache_dir(cmdat_tls, opt_crl_cache_dir);
    CRLMGMT_DATA_set_note(cmdat_tls, "tls connection");

    CRLMGMT_DATA_set_proxy_url(cmdat_new, opt_cdp_proxy);
    CRLMGMT_DATA_set_crl_max_download_size(cmdat_new, opt_crl_maxdownload_size);
    CRLMGMT_DATA_set_crl_cache_dir(cmdat_new, opt_crl_cache_dir);
    CRLMGMT_DATA_set_note(cmdat_new, "new certificates");

    // handle here to start correct demo use case
    if (opt_cmd != NULL) {
        if (strcmp(opt_cmd, "ir") == 0) {
            use_case = imprint;
        } else if (strcmp(opt_cmd, "cr") == 0) {
            use_case = bootstrap;
        } else if (strcmp(opt_cmd, "p10cr") == 0) {
            use_case = pkcs10;
        } else if (strcmp(opt_cmd, "kur") == 0) {
            use_case = update;
        } else if (strcmp(opt_cmd, "rr") == 0) {
            use_case = revocation;
        } else if (strcmp(opt_cmd, "genm") == 0) {
            use_case = genm;
        } else {
            LOG(FL_ERR, "Unknown CMP request command '%s'", opt_cmd);
            goto end;
        }
    } else if (use_case == no_use_case && opt_cmd == NULL) {
        LOG(FL_ERR, "No use case and no '-cmd' option given. Use -help to show usage");
        goto end;
    }

    if (use_case < cmp_usecases) {
        if ((CMPclient(use_case, log_fn)) == CMP_OK)
            rc = EXIT_SUCCESS;
    }
    else {
        if ((client_demo(use_case)) == CMP_OK)
            rc = EXIT_SUCCESS;
    }

 end:
    CRLMGMT_DATA_free(cmdat_new);
    CRLMGMT_DATA_free(cmdat_tls);
    X509_VERIFY_PARAM_free(vpm);
    // TODO fix potential memory leaks; find out why this potentially crashes:
    NCONF_free(config);
    // free possibly created OID NIDs
    OBJ_cleanup();

    if (sec_ctx != NULL && sec_deinit(sec_ctx) == -1)
        rc = EXIT_FAILURE;

#if OPENSSL_VERSION_NUMBER >= 0x10100002L /* TODO remove: */ && 0
# ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks_fp(stderr) <= 0)
        rc = EXIT_FAILURE;
# endif
#endif

    return rc;
}
