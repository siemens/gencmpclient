/*-
 * @file   cmpClientDemo.c
 * @brief  generic CMP client library detailed usage demonstration
 *
 * @author David von Oheimb, CT RDA CST SEA, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2018-2019 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 *  SPDX-License-Identifier: Apache-2.0
 */

#include <securityUtilities.h>
#include <SecUtils/config/config.h>
#include <SecUtils/util/log.h>

#include <genericCMPClient.h>

#include <openssl/ssl.h>

/* needed for OSSL_CMP_ITAV_gen() in function CMPclient_demo() */
#include "../cmpossl/crypto/cmp/cmp_local.h"

#define CONFIG_DEFAULT "config/demo.cnf"
#define DEFAULT_SECTION "default"

#ifdef LOCAL_DEFS
X509 *CREDENTIALS_get_cert(const CREDENTIALS *creds);
#endif

enum use_case { no_use_case,
                imprint, bootstrap, pkcs10, update,
                revocation /* 'revoke' already defined in unistd.h */
};

#define RSA_SPEC "RSA:2048"
#define ECC_SPEC "EC:prime256v1"

/* Option states */
static int opt_index = 1;
static char *arg;

char *opt_config; /* OpenSSL-style configuration file */
CONF *config = NULL; /* OpenSSL configuration structure */
char *opt_section; /* name(s) of config file section(s) to use */
char demo_sections[80];

char *opt_server;
char *opt_proxy;
char *opt_no_proxy;

char *opt_path;
long  opt_msgtimeout;
long  opt_totaltimeout;

char *opt_trusted;
char *opt_untrusted;
char *opt_srvcert;
char *opt_recipient;
char *opt_expect_sender;
bool  opt_ignore_keyusage;
bool  opt_unprotectederrors;
char *opt_extracertsout;
char *opt_cacertsout;

char *opt_ref;
char *opt_secret;
/* TODO re-add creds */
char *opt_cert;
char *opt_key;
char *opt_keypass;
char *opt_digest;
char *opt_mac;
char *opt_extracerts;
bool opt_unprotectedrequests;

char *opt_cmd; /* TODO? add genm */
char *opt_infotype;
char *opt_geninfo;

char *opt_newkeytype;
char *opt_newkey;
char *opt_newkeypass;
char *opt_subject;
char *opt_issuer;
long opt_days;
char *opt_reqexts;
char *opt_sans;
bool opt_san_nodefault;
char *opt_policies;
char *opt_policy_oids;
bool  opt_policy_oids_critical;
long  opt_popo;
char *opt_csr;
char *opt_out_trusted;
bool  opt_implicitconfirm;
bool  opt_disableconfirm;
char *opt_certout;

char *opt_oldcert;
long opt_revreason;

/* TODO? add credentials format options */
/* TODO add opt_engine */

bool opt_tls_used;
/* TODO re-add tls_creds */
char *opt_tls_cert;
char *opt_tls_key;
char *opt_tls_keypass;
char *opt_tls_extra;
char *opt_tls_trusted;
char *opt_tls_host;

/* TODO extend verification options and align with cmpossl/apps/cmp.c */
char *opt_crls_url;
char *opt_crls_file;
bool opt_crls_use_cdp;
char *opt_cdp_url;
#ifndef OPENSSL_NO_OCSP
char *opt_ocsp_url;
#endif

X509_VERIFY_PARAM *vpm;

/*
 * *****************************************************************************
 * Table of configuration options
 * *****************************************************************************
 */
opt_t cmp_opts[] = {
    /* entries must be in the same order as enumerated above!! */
    { "help", OPT_BOOL, {.bool = false}, { NULL },
      "Display this summary"},
    { "config", OPT_TXT, {.txt = CONFIG_DEFAULT}, { &opt_config },
      "Configuration file to use. \"\" = default. Default 'config/demo.cnf'"},
    { "section", OPT_TXT, {.txt = DEFAULT_SECTION}, { &opt_section },
      "Section(s) in config file to get options from. \"\" = 'default'"},

    OPT_SECTION("Message transfer"),
    { "server", OPT_TXT, {.txt = NULL}, { &opt_server },
      "'address[:port]' of the CMP server. Default port 80."},
    OPT_MORE("The address may be a DNS name or an IP address"),
    { "proxy", OPT_TXT, {.txt = NULL}, { &opt_proxy },
      "'["URL_HTTP_PREFIX"]address[:port]' of HTTP(S) proxy. Default port 80."},
    OPT_MORE("Default from environment variable 'http_proxy', else 'HTTP_PROXY'"),
    { "no_proxy", OPT_TXT, {.txt = NULL}, { &opt_no_proxy },
      "List of addresses of servers not use HTTP(S) proxy for."},
    OPT_MORE("Default from environment variable 'no_proxy', else 'NO_PROXY', else none"),
    { "path", OPT_TXT, {.txt = "/"}, { &opt_path },
      "HTTP path (aka CMP alias) at the CMP server. Default \"/\""},
    { "msgtimeout", OPT_NUM, {.num = -1}, { (char **)&opt_msgtimeout },
      "Timeout per CMP message round trip (or 0 for none). Default 120 seconds"},
    { "totaltimeout", OPT_NUM, {.num = -1}, { (char **)&opt_totaltimeout},
      "Overall time an enrollment incl. polling may take. Default: 0 = infinite"},

    OPT_SECTION("Server authentication"),
    { "trusted", OPT_TXT, {.txt = NULL}, { &opt_trusted },
      "Trusted certificates for CMP server authentication (CMP trust anchors)"},
    { "untrusted", OPT_TXT, {.txt = NULL}, { &opt_untrusted },
      "File(s) with intermediate certs for TLS, CMP, and CA chain construction"},
    { "srvcert", OPT_TXT, {.txt = NULL}, { &opt_srvcert },
      "Server certificate to use and directly trust when verifying CMP responses"},
    { "recipient", OPT_TXT, {.txt = NULL}, { &opt_recipient },
      "X509 Name of the recipient"},
    { "expect_sender", OPT_TXT, {.txt = NULL}, { &opt_expect_sender },
      "DN of expected sender (CMP server). Defaults to DN of -srvcert, if provided"},
    { "ignore_keyusage", OPT_BOOL, {.bool = false}, { (char **)&opt_ignore_keyusage },
      "Ignore CMP signer cert key usage, else 'digitalSignature' must be allowed"},
    { "unprotectederrors", OPT_BOOL, {.bool = false}, { (char **) &opt_unprotectederrors },
      "Accept missing or invalid protection of regular error messages and negative"},
    OPT_MORE("certificate responses (ip/cp/kup), revocation responses (rp), and PKIConf"),
    { "extracertsout", OPT_TXT, {.txt = NULL}, { &opt_extracertsout },
      "File to save extra certificates received in the extraCerts field"},
    { "cacertsout", OPT_TXT, {.txt = NULL}, { &opt_cacertsout },
      "File to save CA certificates received in the caPubs field of 'ip' messages"},

    OPT_SECTION("Client authentication"),
    { "ref", OPT_TXT, {.txt = NULL}, { &opt_ref },
      "Reference value to use as senderKID in case no -cert is given"},
    { "secret", OPT_TXT, {.txt = NULL}, { &opt_secret },
      "Secret value for authentication with a pre-shared key (PBM)"},
    { "cert", OPT_TXT, {.txt = NULL}, { &opt_cert },
      "Client certificate (plus any extra one), needed unless using -secret for PBM."},
    OPT_MORE("This also used as default reference for subject DN and SANs"),
    { "key", OPT_TXT, {.txt = NULL}, { &opt_key },
      "Key for the client certificate"},
    { "keypass", OPT_TXT, {.txt = NULL}, { &opt_keypass },
      "Password for the client's key"},
    { "digest", OPT_TXT, {.txt = NULL}, { &opt_digest },
      "Digest alg to use in msg protection and POPO signatures. Default \"sha256\""},
    { "mac", OPT_TXT, {.txt = NULL}, { &opt_mac},
      "MAC algorithm to use in PBM-based message protection. Default \"hmac-sha1\""},
    { "extracerts", OPT_TXT, {.txt = NULL}, { &opt_extracerts },
      "File(s) with certificates to append in extraCerts field of outgoing messages"},
    { "unprotectedrequests", OPT_BOOL, {.bool = false}, { (char **) &opt_unprotectedrequests },
      "Send messages without CMP-level protection"},

    OPT_SECTION("Generic message"),
    { "cmd", OPT_TXT, {.txt = NULL}, { &opt_cmd },
      "CMP request to send: ir/cr/p10cr/kur/rr. Overwrites 'use_case' if given"}, /* TODO? add genm */
    { "infotype", OPT_TXT, {.txt = NULL}, { &opt_infotype },
      "InfoType name for requesting specific info in genm, currently ignored"},
    { "geninfo", OPT_TXT, {.txt = NULL}, { &opt_geninfo },
      "generalInfo to place in request PKIHeader with type and integer value"},
    OPT_MORE("given in the form <OID>:int:<n>, e.g. \"1.2.3:int:987\""),

    OPT_SECTION("Certificate enrollment"),
    { "newkeytype", OPT_TXT, {.txt = NULL}, { &opt_newkeytype },
      "Type of key to generate, e.g., \"ECC\" or \"RSA\""},
    { "newkey", OPT_TXT, {.txt = NULL}, { &opt_newkey },
      "Key to use for cert request (defaulting to -key) unless -newkeytype is given;"},
    OPT_MORE("File to save new generated key if -newkeytype is given"),
    { "newkeypass", OPT_TXT, {.txt = NULL}, { &opt_newkeypass },
      "Password for the file given for -newkey"},
    { "subject", OPT_TXT, {.txt = NULL}, { &opt_subject },
      "Distinguished Name (DN) of subject to use in the requested cert template"},
    { "issuer", OPT_TXT, {.txt = NULL}, { &opt_issuer },
      "DN of the issuer to place in the requested certificate template"},
    { "days", OPT_NUM, {.num = 0}, { (char **) &opt_days },
      "Requested validity time of new cert in number of days"},
    { "reqexts", OPT_TXT, {.txt = NULL}, { &opt_reqexts },
      "Name of config file section defining certificate request extensions"},
    { "sans", OPT_TXT, {.txt = NULL}, { &opt_sans },
      "Subject Alt Names (IPADDR/DNS/URI) to add as (critical) cert req extension"},
    { "san_nodefault", OPT_BOOL, {.bool = false}, { (char **) &opt_san_nodefault},
      "Do not take default SANs from reference certificate (see -oldcert)"},
    { "policies", OPT_TXT, {.txt = NULL}, { &opt_policies},
      "Name of config file section defining policies request extension"},
    { "policy_oids", OPT_TXT, {.txt = NULL}, { &opt_policy_oids},
      "Policy OID(s) to add as certificate policies request extension"},
    { "policy_oids_critical", OPT_BOOL, {.bool = false}, { (char **) &opt_policy_oids_critical},
      "Flag the policy OID(s) given with -policies_ as critical"},
    { "popo", OPT_NUM, {.num = OSSL_CRMF_POPO_NONE - 1}, { (char **) &opt_popo },
      "Proof-of-Possession (POPO) method to use for ir/cr/kur where"},
    OPT_MORE("-1 = NONE, 0 = RAVERIFIED, 1 = SIGNATURE (default), 2 = KEYENC"),
    { "csr", OPT_TXT, {.txt = NULL}, { &opt_csr },
      "CSR file in PKCS#10 format to use in p10cr for legacy support"},
    { "out_trusted", OPT_TXT, {.txt = NULL}, { &opt_out_trusted },
      "File(s) with certs to trust when verifying newly enrolled certs; defaults to -srvcert"},
    { "implicitconfirm", OPT_BOOL, {.bool = false}, { (char **) &opt_implicitconfirm },
      "Request implicit confirmation of newly enrolled certificates"},
    { "disableconfirm", OPT_BOOL, {.bool = false}, { (char **) &opt_disableconfirm },
      "Do not confirm newly enrolled certificates w/o requesting implicit confirm"},
    { "certout", OPT_TXT, {.txt = NULL}, { &opt_certout },
      "File to save newly enrolled certificate"},

    OPT_SECTION("Certificate update and revocation"),
    { "oldcert", OPT_TXT, {.txt = NULL}, { &opt_oldcert },
      "Certificate to be updated (defaulting to -cert) or to be revoked in rr;"},
    OPT_MORE("Its issuer is used as recipient unless -srvcert, -recipient or -issuer given"),
    { "revreason", OPT_NUM, {.num = CRL_REASON_NONE}, { (char **) &opt_revreason },
      "Reason code to include in revocation request (RR)."},
    OPT_MORE("Values: 0..6, 8..10 (see RFC5280, 5.3.1) or -1. Default -1 = none included"),

    /* TODO? OPT_SECTION("Credentials format"), */
    /* TODO add opt_engine */

    OPT_SECTION("TLS connection"),
    { "tls_used", OPT_BOOL, {.bool = false}, { (char **) &opt_tls_used },
      "Force using TLS (also when other TLS options are not set)"},
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

    /* TODO? OPT_SECTION("Client-side debugging"), */

    OPT_SECTION("Specific CMP and TLS certificate verification"),
    /* TODO extend verification options and align with cmpossl/apps/cmp.c */
    { "crls_url", OPT_TXT, {.txt = NULL}, {&opt_crls_url},
      "Use given URL as (primary) CRL source when verifying certs"},
    { "crls_file", OPT_TXT, {.txt = NULL}, {&opt_crls_file},
      "Use given local file(s) as (primary) CRL source"},
    { "crls_use_cdp", OPT_BOOL, {.bool = false}, { (char **) &opt_crls_use_cdp },
      "Retrieve CRLs from CDPs given in certs as secondary (fallback) source"},
    { "cdp_url", OPT_TXT, {.txt = NULL}, {&opt_cdp_url},
      "Use given URL(s) as secondary CRL source"},
#ifndef OPENSSL_NO_OCSP
    { "ocsp_url", OPT_TXT, {.txt = NULL}, {&opt_ocsp_url},
      "Use OCSP with given URL as primary address of OCSP responder"},
#endif

    /* TODO? add OPT_V_OPTIONS or the like */
    /*
     * subsumes:
     * {"crl_check_all", OPT_CRLALL, '-',
     *  "Check CRLs not only for leaf certificate but for full cert chain"},
     */

    { NULL, OPT_TXT, {.txt = NULL}, { NULL }, NULL}
};

/* OPTION_CHOICE values must be in the same order as enumerated above!! */
typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_SECTION_1, OPT_HELP, OPT_CONFIG,
    OPT_SECTION,

    OPT_SECTION_2,
    OPT_SERVER, OPT_PROXY, OPT_NO_PROXY, OPT_PATH,
    OPT_MSGTIMEOUT, OPT_TOTALTIMEOUT,

    OPT_SECTION_3,
    OPT_TRUSTED, OPT_UNTRUSTED, OPT_SRVCERT, OPT_RECIPIENT,
    OPT_EXPECT_SENDER, OPT_IGNORE_KEYUSAGE, OPT_UNPROTECTEDERRORS, OPT_EXTRACERTSOUT,
    OPT_CACERTSOUT,

    OPT_SECTION_4,
    OPT_REF, OPT_SECRET, OPT_CERT, OPT_KEY,
    OPT_KEYPASS, OPT_DIGEST, OPT_MAC, OPT_EXTRACERTS,
    OPT_UNPROTECTEDREQUESTS,

    OPT_SECTION_5,
    OPT_CMD, OPT_INFOTYPE, OPT_GENINFO, OPT_MORE_STR_1,

    OPT_SECTION_6,
    OPT_NEWKEY, OPT_NEWKEYPASS, OPT_SUBJECT, OPT_ISSUER,
    OPT_DAYS, OPT_REQEXTS, OPT_SANS, OPT_SAN_NODEFAULT,
    OPT_POLICIES, OPT_POLICY_OIDS, OPT_POLICY_OIDS_CRITICAL,
    OPT_POPO, OPT_CSR, OPT_OUT_TRUSTED,
    OPT_IMPLICITCONFIRM, OPT_DISABLECONFIRM, OPT_CERTOUT,

    OPT_SECTION_7,
    OPT_OLDCERT, OPT_REVREASON, OPT_MORE_STR_2,

    OPT_SECTION_8,
    OPT_NEWKEYTYPE,

    OPT_SECTION_9,
    OPT_TLS_USED, OPT_TLS_CERT, OPT_TLS_KEY, OPT_TLS_KEYPASS,
    OPT_TLS_EXTRA, OPT_TLS_TRUSTED, OPT_TLS_HOST,

    OPT_SECTION_10,
    OPT_CRLS_URL, OPT_CRLS_FILE,
#ifndef OPENSSL_NO_OCSP
    OPT_OCSP_URL,
#endif
    OPT_CRLS_USE_CDP, OPT_CDP_URL,

    OPT_END
} OPTION_CHOICE;


const char *tls_ciphers = NULL; /* or, e.g., "HIGH:!ADH:!LOW:!EXP:!MD5:@STRENGTH"; */

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
        LOG(FL_ERR, "error: unable to use TLS extra certs");
    return res;
}

static int set_gennames(OSSL_CMP_CTX *ctx, char *names, const char *desc)
{
    char *next;

    for (; names != NULL; names = next) {
        GENERAL_NAME *n;
        next = UTIL_next_item(names);

        if (strcmp(names, "critical") == 0) {
            (void)OSSL_CMP_CTX_set_option(ctx,
                                          OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL, 1);
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
            LOG(FL_ERR, "out of memory");
            return 0;
        }
        GENERAL_NAME_free(n);
    }
    return 1;
}

SSL_CTX *setup_TLS(void)
{
#ifdef SEC_NO_TLS
    fprintf(stderr, "TLS is not enabled in this build\n");
    return NULL;
#else

    STACK_OF(X509_CRL) *crls = NULL;
    CREDENTIALS *tls_creds = NULL;
    SSL_CTX *tls = NULL;

    const char *trusted = opt_tls_trusted;
    X509_STORE *truststore = STORE_load(trusted, "trusted certs for TLS level");
    if (truststore == NULL)
        goto err;

# if 0
    const char *crls_files = opt_crls_file;
    crls = CRLs_load(crls_files, "CRLs for TLS level");
    if (crls == NULL)
        goto err;
# endif
    const X509_VERIFY_PARAM *vpm = NULL;
    const bool full_chain = true;
    const bool use_CDPs = false;
    const char *CRLs_url = NULL; /* or: opt_crls_url */
    const bool use_AIAs = true;
    const char *OCSP_url = opt_ocsp_url;
    const bool try_stapling = (use_AIAs || OCSP_url != NULL)
        && OPENSSL_VERSION_NUMBER >= 0x1010001fL;
    if (!STORE_set_parameters(truststore, vpm,
                              full_chain, try_stapling, crls,
                              use_CDPs, CRLs_url,
                              use_AIAs, OCSP_url))
        goto err;

    tls_creds = CREDENTIALS_load(opt_tls_cert, opt_tls_key, opt_tls_keypass,
                                 "credentials for TLS level");
    if (tls_creds == NULL)
        goto err;
    const STACK_OF(X509) *untrusted_certs = NULL;
    /*
     * TODO maybe also add untrusted certs to help building chain of TLS client
     * and checking stapled OCSP responses
     */
    const int security_level = -1;
    tls = TLS_new(truststore, untrusted_certs, tls_creds, tls_ciphers, security_level);

    /* If present we append to the list also the certs from opt_tls_extra */
    if (opt_tls_extra != NULL) {
        STACK_OF(X509) *tls_extra = CERTS_load(opt_tls_extra, "extra certificates for TLS");
        if (tls_extra == NULL ||
            !SSL_CTX_add_extra_chain_free(tls, tls_extra))
            goto err;
    }

 err:
    STORE_free(truststore);
    CRLs_free(crls);
    CREDENTIALS_free(tls_creds);
    return tls;
#endif
}

X509_STORE *setup_CMP_truststore(void)
{
    STACK_OF(X509_CRL) *crls = NULL;
    X509_STORE *cmp_truststore = NULL;

    const char *crls_files = opt_crls_use_cdp == true ? opt_cdp_url : opt_crls_file;

    if (crls_files != NULL) {
        crls = CRLs_load(crls_files, "CRLs for CMP level");
        if (crls == NULL)
            goto err;
    }

    const char *trusted_cert_files = opt_trusted;
    cmp_truststore = STORE_load(trusted_cert_files, "trusted certs for CMP level");
    if (cmp_truststore == NULL)
        goto err;

    const X509_VERIFY_PARAM *vpm = NULL;
    const bool full_chain = true;
    const bool try_stapling = false;
    const bool use_CDPs = true;
    const char *CRLs_url = opt_crls_url;
    const bool use_AIAs = false;
    const char *OCSP_url = NULL; /* or: opt_ocsp_url */
    if (!STORE_set_parameters(cmp_truststore, vpm,
                              full_chain, try_stapling, crls,
                              use_CDPs, CRLs_url,
                              use_AIAs, OCSP_url)) {
        STORE_free(cmp_truststore);
        cmp_truststore = NULL;
    }

 err:
    CRLs_free(crls);
    /* X509_VERIFY_PARAM_free(vpm); */
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
        LOG(FL_ERR, "cannot have policies both via -policies and via -policy_oids");
        goto err;
    }

    if (opt_policy_oids_critical) {
        if (opt_policy_oids == NULL)
            LOG(FL_WARN, "-opt_policy_oids_critical has no effect unless -policy_oids is given");
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_POLICIES_CRITICAL, 1)) {
            LOG(FL_ERR, "Failed to set 'setPoliciesCritical' field of CMP context");
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
            LOG(FL_ERR, "out of memory");
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
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return NULL;
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
            LOG(FL_ERR, "Out of memory");
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
            LOG(FL_WARN, "-opt_san_nodefault has no effect when -sans is used");
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT, 1)) {
            LOG(FL_ERR, "Failed to set 'SubjectAltName_nodefault' field of CMP context");
            goto err;
        }
    }

    if (!set_gennames(ctx, opt_sans, "Subject Alternative Name")) {
        LOG(FL_ERR, "Failed to set 'Subject Alternative Name' of CMP context");
        err = 10;
        goto err;
    }

   err:
    return err;
}


int setup_ctx(CMP_CTX *ctx)
{
    OSSL_cmp_log_cb_t log_fn = NULL;
    CMP_err err = CMPclient_init(log_fn);
    if (err != CMP_OK)
        return err;

    err = set_name(opt_expect_sender, OSSL_CMP_CTX_set1_expected_sender,
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
                LOG(FL_ERR, "Failed to set 'extraCerts' field of CMP context");
                sk_X509_pop_free(certs, X509_free);
                err = 9;
                goto err;
            }
            sk_X509_pop_free(certs, X509_free);
        }
    }

    if (opt_popo < OSSL_CRMF_POPO_NONE - 1 || opt_popo > OSSL_CRMF_POPO_KEYENC) {
        LOG(FL_ERR, "Invalid value '%d' for popo method (must be between -1 and 2)", opt_popo);
        goto err;
    }

    /* set option flags directly via CMP API */
    if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_ERRORS, opt_unprotectederrors)
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IGNORE_KEYUSAGE, opt_ignore_keyusage)
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_VALIDITYDAYS, (int)opt_days)
        || (opt_popo >= OSSL_CRMF_POPO_NONE
            && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_POPOMETHOD, (int)opt_popo))
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DISABLECONFIRM, opt_disableconfirm)
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_SEND, opt_unprotectedrequests)) {
        LOG(FL_ERR, "Failed to set option flags of CMP context");
        goto err;
    }

    if (opt_geninfo != NULL) {
        long value;
        ASN1_OBJECT *type;
        ASN1_INTEGER *aint;
        ASN1_TYPE *val;
        OSSL_CMP_ITAV *itav;
        char *endstr;
        char *valptr = strchr(opt_geninfo, ':');

        if (valptr == NULL) {
            LOG(FL_ERR, "missing ':' in -geninfo option");
            goto err;
        }
        valptr[0] = '\0';
        valptr++;

        if (strncmp(valptr, "int:", 4) != 0) {
            LOG(FL_ERR, "missing 'int:' in -geninfo option");
            goto err;
        }
        valptr += 4;

        value = strtol(valptr, &endstr, 10);
        if (endstr == valptr || *endstr != '\0') {
            LOG(FL_ERR, "cannot parse int in -geninfo option");
            goto err;
        }

        type = OBJ_txt2obj(opt_geninfo, 1);
        if (type == NULL) {
            LOG(FL_ERR, "cannot parse OID in -geninfo option");
            goto err;
        }

        aint = ASN1_INTEGER_new();
        if (aint == NULL || !ASN1_INTEGER_set(aint, value)) {
            LOG(FL_ERR, "cannot set ASN1 integer");
            err = 11;
            goto err;
        }

        val = ASN1_TYPE_new();
        if (val == NULL) {
            LOG(FL_ERR, "cannot create new ASN1 type");
            err = 12;
            ASN1_INTEGER_free(aint);
            goto err;
        }
        ASN1_TYPE_set(val, V_ASN1_INTEGER, aint);
        itav = OSSL_CMP_ITAV_gen(type, val);
        if (itav == NULL) {
            LOG(FL_ERR, "Unable to create 'OSSL_CMP_ITAV' structure");
            err = 13;
            ASN1_TYPE_free(val);
            goto err;
        }

        if (!OSSL_CMP_CTX_push0_geninfo_ITAV(ctx, itav)) {
            LOG(FL_ERR, "Failed to add an ITAV for geninfo of the PKI message header");
            err = 14;
            OSSL_CMP_ITAV_free(itav);
            goto err;
        }
    }

    err = CMP_OK;

 err:
    return err;
}

CMP_err prepare_CMP_client(CMP_CTX **pctx, OPTIONAL OSSL_cmp_log_cb_t log_fn,
                           OPTIONAL CREDENTIALS *cmp_creds)
{
    if (opt_srvcert != NULL && opt_trusted != NULL)
        LOG(FL_WARN, "-trusted option is ignored since -srvcert option is present");

    X509_STORE *cmp_truststore = opt_trusted == NULL ? NULL : setup_CMP_truststore();
    STACK_OF(X509) *untrusted_certs = opt_untrusted == NULL ? NULL :
        CERTS_load(opt_untrusted, "untrusted certs for CMP");
    if ((cmp_truststore == NULL && opt_trusted != NULL)
            || (untrusted_certs == NULL && opt_untrusted != NULL))
        return 2;

    CMP_err err = 3;
    X509_STORE *new_cert_truststore = NULL;
    const char *new_cert_trusted = opt_out_trusted == NULL ? opt_srvcert : opt_out_trusted;
    if (new_cert_trusted != NULL) {
        LOG(FL_INFO, "Using '%s' as cert trust store for verifying new cert", new_cert_trusted);
        new_cert_truststore = STORE_load(new_cert_trusted, "trusted certs for verifying new cert");
        if (new_cert_truststore == NULL)
            goto err;
    }
    /* no revocation done for newly enrolled cert */

    OSSL_cmp_transfer_cb_t transfer_fn = NULL; /* default HTTP(S) transfer */
    const bool implicit_confirm = opt_implicitconfirm;

    if ((int)opt_totaltimeout < -1) {
        LOG(FL_ERR, "only non-negative values allowed for opt_totaltimeout");
        goto err;
    }
    err = CMPclient_prepare(pctx, log_fn,
                            cmp_truststore, opt_recipient,
                            untrusted_certs,
                            cmp_creds, opt_digest, opt_mac,
                            transfer_fn, (int)opt_totaltimeout,
                            new_cert_truststore, implicit_confirm);
    CERTS_free(untrusted_certs);
    STORE_free(new_cert_truststore);
    if (err != CMP_OK)
        goto err;

    if (opt_srvcert != NULL) {
        sec_file_format format = FILES_get_format(opt_srvcert);
        X509 *srvcert = FILES_load_cert(opt_srvcert, format, NULL /* pass */, "directly trusted CMP server certificate");
        if (srvcert == NULL || !OSSL_CMP_CTX_set1_srvCert(*pctx, srvcert))
            err = 4;
        X509_free(srvcert);
    }
 err:
    STORE_free(cmp_truststore);
    return err;
}

static int reqExtensions_have_SAN(X509_EXTENSIONS *exts)
{
    if (exts == NULL)
        return 0;
    return X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1) >= 0;
}

/* TODO move to SecUtils/src/config/opt.c */
/*
 * return OPTION_choice index on success, -1 if options does not match and
 * OPT_END if all options are handled
 */
static int opt_next(int argc, char **argv)
{
    int i;
    char *param;

 retry:
    /* Look at current arg; at end of the list? */
    arg = NULL;
    param = argv[opt_index];
    if (param == NULL)
        return OPT_END;

    /* If word doesn't start with a -, it failed to parse all options. */
    if (*param != '-') {
        LOG(FL_ERR, "Failed to parse all options");
        arg = param;
        return OPT_ERR;
    }

    /* if starting with '-', snip it of */
    if (*param == '-')
        param++;

    opt_index++;
    for (i = 0; i < OPT_END; i++) {
        /* already handled, check next option */
        if (strcmp(param, "section") == 0 ||
            strcmp(param, "config") == 0) {
            opt_index++;
            goto retry;
        }
        if (strcmp(param, "help") == 0)
            return OPT_HELP;
        if (strcmp(param, cmp_opts[i].name) == 0) {
            /* Boolean options have no parameter, just return index */
            if (cmp_opts[i].type == OPT_BOOL)
                return i;
            if (argv[opt_index] == NULL) {
                LOG(FL_ERR, "Option -%s needs a value", param);
                return OPT_ERR;
            }
            /* check non-bool options for parameters */
            if (cmp_opts[i].type == OPT_TXT && *argv[opt_index] == '-') {
                LOG(FL_ERR, "Option -%s needs a value", param);
                return OPT_ERR;
            }
            arg = argv[opt_index];
            opt_index++;
            return i;
        }
    }

    if (i == OPT_END) {
        /* in case of unknown option, return option with leading '-' */
        arg = --param;
        return OPT_ERR;
    }

    if (opt_index == argc)
        return OPT_END;
    return OPT_ERR;
}

/* TODO move to SecUtils/src/config/opt.c */
/*
 * returns -1 when printing option help, 0 on success
 * and 1 on error
 */
static int get_opts(int argc, char **argv)
{
    OPTION_CHOICE o;

    while ((o = opt_next(argc, argv)) != OPT_END) {
        if (o == OPT_ERR) {
            LOG(FL_ERR, "Unknown option '%s' used", arg);
            return 1;
        }
        if (o == OPT_HELP) {
            return -1;
        }

        switch (cmp_opts[o].type) {
        case OPT_TXT:
            if (arg[0] == '\0') {
                *cmp_opts[o].varref_u.txt = cmp_opts[o].default_value.txt;
                break;
            }
            *cmp_opts[o].varref_u.txt = arg;
            break;
        case OPT_NUM:
            if (arg[0] == '\0') {
                *cmp_opts[o].varref_u.num = cmp_opts[o].default_value.num;
                break;
            }
            if ((*cmp_opts[o].varref_u.num = UTIL_atoint(arg)) == INT_MIN) {
                LOG(FL_ERR, "Can't parse '%s' as number", arg);
                return 1;
            }
            break;
        case OPT_BOOL:
            *cmp_opts[o].varref_u.bool = true;
            break;
        default:
            return 1;
        }
    }
    return 0;
}

int setup_transfer(CMP_CTX *ctx)
{
    CMP_err err;

    const char *path = opt_path;
    const char *server = opt_tls_used ? opt_tls_host : opt_server;

    if ((int)opt_msgtimeout < -1) {
        LOG(FL_ERR, "only non-negative values allowed for opt_msgtimeout");
        err = 16;
        goto err;
    }

    SSL_CTX *tls = NULL;
    if (opt_tls_used && (tls = setup_TLS()) == NULL) {
        LOG(FL_ERR, "Unable to setup TLS for CMP client");
        err = 17;
        goto err;
    }

    err = CMPclient_setup_HTTP(ctx, server, path, (int)opt_msgtimeout,
                               tls, opt_proxy, opt_no_proxy);
#ifndef SEC_NO_TLS
    TLS_free(tls);
#endif
    if (err != CMP_OK) {
        LOG(FL_ERR, "Unable to setup HTTP for CMP client");
        goto err;
    }
 err:
    return err;
}

static int CMPclient_demo(enum use_case use_case)
{
    OSSL_cmp_log_cb_t log_fn = NULL;
    CMP_err err = CMPclient_init(log_fn);
    if (err != CMP_OK)
        return err;

    CMP_CTX *ctx = NULL;
    EVP_PKEY *new_pkey = NULL;
    X509_EXTENSIONS *exts = NULL;
    CREDENTIALS *new_creds = NULL;
    CREDENTIALS *cmp_creds;

    if (opt_infotype != NULL)  /* TODO? implement when genm is supported */
        LOG(FL_WARN, "-infotype option is ignored as long as 'genm' is not supported");

    if (use_case == update) {
        if (opt_secret != NULL) {
            LOG(FL_WARN, "-secret option is ignored for 'kur' commands");
            opt_secret = NULL;
        }
    }
    if (!opt_unprotectedrequests && !opt_secret && !(opt_cert && opt_key)) {
        LOG(FL_ERR, "must give client credentials unless -unprotectedrequests is set");
        err = 1;
        goto err;
    }

    if (opt_ref == NULL && opt_cert == NULL && opt_subject == NULL) {
        /* cert or subject should determine the sender */
        /* TODO maybe else take as sender default the subjectName of oldCert or p10cr */
        LOG(FL_ERR, "must give -ref if no -cert and no -subject given");
        err = 1;
        goto err;
    }
    if (!opt_secret && ((opt_cert == NULL) != (opt_key == NULL))) {
        LOG(FL_ERR, "must give both -cert and -key options or neither");
        err = 1;
        goto err;
    }

    if (use_case == pkcs10 && opt_csr == NULL) {
        LOG(FL_ERR, "-csr option is missing for command 'p10cr'");
        err = 21;
        goto err;
    }
    if (use_case == revocation && opt_oldcert == NULL) {
        LOG(FL_ERR, "-oldcert option is missing for command 'rr' (revocation)");
        err = 21;
        goto err;
    }
    const char *const creds_desc = "credentials for CMP level";
    cmp_creds =
        use_case != update && opt_secret != NULL
        /* use PBM except for kur if secret is present */
        ? CREDENTIALS_new(NULL, NULL, NULL, opt_secret, opt_ref)
        : CREDENTIALS_load(opt_cert, opt_key, opt_keypass, creds_desc);
    if (cmp_creds == NULL) {
        LOG(FL_ERR, "Unable to set up credentials for CMP level");
        err = 1;
        goto err;
    }

    err = prepare_CMP_client(&ctx, log_fn, cmp_creds);
    CREDENTIALS_free(cmp_creds);
    if (err != CMP_OK) {
        LOG(FL_ERR, "Failed to prepare CMP client");
        goto err;
    }

    if ((err = setup_ctx(ctx)) != CMP_OK) {
        LOG(FL_ERR, "Failed to prepare CMP client");
        goto err;
    }

    if (use_case == pkcs10 || use_case == revocation) {
        if (opt_newkeytype != 0)
            LOG(FL_WARN, "-newkeytype option is ignored for 'p10cr' and 'rr' commands");
        if (opt_newkey != 0)
            LOG(FL_WARN, "-newkey option is ignored for 'p10cr' and 'rr' commands");
        if (opt_days != 0)
            LOG(FL_WARN, "-days option is ignored for 'p10cr' and 'rr' commands");
        if (opt_popo != OSSL_CRMF_POPO_NONE - 1)
            LOG(FL_WARN, "-popo option is ignored for commands other than 'ir', 'cr', and 'p10cr'");
    } else {
        if (opt_newkeytype != NULL) {
            if (opt_newkey == NULL) {
                LOG(FL_ERR, "Missing -newkey option for saving the new key");
                err = 18;
                goto err;
            }
            const char *key_spec = strcmp(opt_newkeytype, "RSA") == 0 ? RSA_SPEC : ECC_SPEC;
            new_pkey = KEY_new(key_spec);
            if (new_pkey == NULL) {
                LOG(FL_ERR, "Unable to generate new private key according to specification '%s'",
                    key_spec);
                err = 18;
                goto err;
            }
        }
        else {
            if (opt_newkey == NULL && opt_key == NULL) {
                LOG(FL_ERR, "Missing -newkeytype or -newkey or -key option");
                err = 18;
                goto err;
            }
            if (opt_newkey != NULL) {
                sec_file_format format = FILES_get_format(opt_cacertsout);
                new_pkey = FILES_load_key_autofmt(opt_newkey, format, false,
                                                  opt_newkeypass, NULL /* engine */,
                                                  "private key to use for certificate request");
                if (new_pkey == NULL) {
                    err = 18;
                    goto err;
                }
            }
        }
    }

    if (use_case == imprint || use_case == bootstrap) {
        if (reqExtensions_have_SAN(exts) && opt_sans != NULL) {
            LOG(FL_ERR, "Cannot have Subject Alternative Names both via -reqexts and via -sans");
            err = CMP_R_MULTIPLE_SAN_SOURCES;
            goto err;
        }

        err = setup_cert_template(ctx);
        if (err != CMP_OK)
            goto err;
        if ((exts = setup_X509_extensions(ctx)) == NULL) {
            LOG(FL_ERR, "Unable to set up X509 extensions for CMP client");
            err = 19;
            goto err;
        }
    } else {
        if (opt_subject != NULL) {
            if (opt_ref == NULL && opt_cert == NULL) {
                /* use subject as default sender */
                err = set_name(opt_issuer, OSSL_CMP_CTX_set1_subjectName, ctx, "subject");
                if (err != CMP_OK)
                    goto err;
            } else {
                LOG(FL_WARN, "-subject option is ignored for commands other than 'ir' and 'cr'");
            }
        }
        if (opt_issuer != NULL)
            LOG(FL_WARN, "-issuer option is ignored for commands other than 'ir' and 'cr'");
        if (opt_reqexts != NULL)
            LOG(FL_WARN, "-reqexts option is ignored for commands other than 'ir' and 'cr'");
        if (opt_san_nodefault)
            LOG(FL_WARN, "-san_nodefault option is ignored for commands other than 'ir' and 'cr'");
        if (opt_sans != NULL)
            LOG(FL_WARN, "-sans option is ignored for commands other than 'ir' and 'cr'");
        if (opt_policies != NULL)
            LOG(FL_WARN, "-policies option is ignored for commands other than 'ir' and 'cr'");
        if (opt_policy_oids != NULL)
            LOG(FL_WARN, "-policy_oids option is ignored for commands other than 'ir' and 'cr'");
    }

    if (use_case != pkcs10 && opt_csr != NULL)
        LOG(FL_WARN, "-csr option is ignored for commands other than 'p10cr'");
    if (use_case != update && use_case != revocation && opt_oldcert != NULL)
        LOG(FL_WARN, "-oldcert option is ignored for commands other than 'kur' and 'rr'");
    if (use_case == revocation) {
        if (opt_implicitconfirm)
            LOG(FL_WARN, "-implicitconfirm option is ignored for 'rr' commands");
        if (opt_disableconfirm)
            LOG(FL_WARN, "-disableconfirm option is ignored for 'rr' commands");
        if (opt_certout != NULL)
            LOG(FL_WARN, "-certout option is ignored for 'rr' commands");
    } else {
        if (opt_revreason != CRL_REASON_NONE)
            LOG(FL_WARN, "-revreason option is ignored for commands other than 'rr'");
    }

    if ((err = setup_transfer(ctx)) != CMP_OK)
        goto err;

    switch (use_case) {
    case imprint:
        err = CMPclient_imprint(ctx, &new_creds, new_pkey, opt_subject, exts);
        break;
    case bootstrap:
        err = CMPclient_bootstrap(ctx, &new_creds, new_pkey, opt_subject, exts);
        break;
    case pkcs10:
        {
            X509_REQ *csr = FILES_load_csr_autofmt(opt_csr, FORMAT_PEM, "PKCS#10 CSR for p10cr");
            if (csr == NULL) {
                err = 15;
                goto err;
            }
            err = CMPclient_pkcs10(ctx, &new_creds, csr);
            X509_REQ_free(csr);
        }
        break;
    case update:
        if (opt_oldcert == NULL) {
            err = CMPclient_update(ctx, &new_creds, new_pkey);
        } else {
            sec_file_format format = FILES_get_format(opt_oldcert);
            X509 *oldcert = FILES_load_cert(opt_oldcert, format, opt_keypass, "certificate to be updated");
            if (oldcert == NULL)
                err = 19;
            else
                err = CMPclient_update_anycert(ctx, &new_creds, oldcert, new_pkey);
            X509_free(oldcert);
        }
        break;
    case revocation:
        if ((int)opt_revreason < CRL_REASON_NONE
                || (int)opt_revreason > CRL_REASON_AA_COMPROMISE
                || (int)opt_revreason == 7) {
            LOG(FL_ERR, "invalid revreason. Valid values are -1..6, 8..10.");
            err = 20;
            goto err;
        }
        {
            sec_file_format format = FILES_get_format(opt_oldcert);
            X509 *oldcert = FILES_load_cert(opt_oldcert, format, opt_keypass, "certificate to be revoked");
            if (oldcert == NULL)
                err = 21;
            else
                err = CMPclient_revoke(ctx, oldcert, (int)opt_revreason);
            X509_free(oldcert);
        }
        /* CmpWsRa does not accept CRL_REASON_NONE: "missing crlEntryDetails for REVOCATION_REQ" */
        break;
    default:
        LOG(FL_ERR, "Unknown use case '%d' used", use_case);
        err = 21;
    }
    if (err != CMP_OK) {
        LOG(FL_ERR, "Failed to perform CMP request");
        goto err;
    }

    if (opt_cacertsout != NULL) {
        sec_file_format format = FILES_get_format(opt_cacertsout);
        STACK_OF(X509) *certs = OSSL_CMP_CTX_get1_caPubs(ctx);
        if (format == FORMAT_UNDEF) {
            LOG(FL_ERR, "Failed to determine format for file endings of '%s'", opt_cacertsout);
            err = 22;
            goto err;
        }
        if (sk_X509_num(certs) > 0
                && FILES_store_certs(certs, opt_cacertsout, format, "CA") < 0) {
            LOG(FL_ERR, "Failed to store '%s'", opt_cacertsout);
            sk_X509_pop_free(certs, X509_free);
            err = 23;
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    if (opt_extracertsout != NULL) {
        sec_file_format format = FILES_get_format(opt_extracertsout);
        STACK_OF(X509) *certs = OSSL_CMP_CTX_get1_extraCertsIn(ctx);
        if (format == FORMAT_UNDEF) {
            LOG(FL_ERR, "Failed to determine format for file endings of '%s'", opt_extracertsout);
            err = 24;
            goto err;
        }
        if (sk_X509_num(certs) > 0
                && FILES_store_certs(certs, opt_extracertsout, format, "extra") < 0) {
            LOG(FL_ERR, "Failed to store '%s'", opt_extracertsout);
            sk_X509_pop_free(certs, X509_free);
            err = 25;
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    if (use_case != revocation) {
        const char *new_desc = "newly enrolled certificate and related chain and key";
        if (!CREDENTIALS_save(new_creds, opt_certout, opt_newkey, opt_newkeypass, new_desc)) {
            LOG(FL_ERR, "Failed to save newly enrolled credentials");
            err = 26;
            goto err;
        }
    }

 err:
    CMPclient_finish(ctx); /* this also frees ctx */
    KEY_free(new_pkey);
    EXTENSIONS_free(exts);
    CREDENTIALS_free(new_creds);

    LOG_close(); /* not really needed since done also in sec_deinit() */
    if (err != CMP_OK) {
        LOG(FL_ERR, "CMPclient error %d", err);
    }
    return err;
}

int main(int argc, char *argv[])
{
    int i;
    int rc = 0;

#if OPENSSL_VERSION_NUMBER >= 0x10100002L
# ifndef OPENSSL_NO_CRYPTO_MDEBUG
    char *p = getenv("OPENSSL_DEBUG_MEMORY");
    if (p != NULL && strcmp(p, "on") == 0)
        CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
# endif
#endif

    sec_ctx *sec_ctx = sec_init();
    if (sec_ctx == NULL) {
        LOG(FL_ERR, "failure getting SecUtils ctx");
        return EXIT_FAILURE;
    }

    BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
    enum use_case use_case = no_use_case; /* default */
    if (argc > 1) {
        if (strcmp(argv[1], "imprint") == 0) {
            use_case = imprint;
        } else if (strcmp(argv[1], "bootstrap") == 0) {
            use_case = bootstrap;
        } else if (strcmp(argv[1], "update") == 0) {
            use_case = update;
        } else if (strcmp(argv[1], "revoke") == 0) {
            use_case = revocation;
        } else if (strcmp(argv[1], "-help") == 0) {
            LOG(FL_INFO, "\nUsage: %s [imprint | bootstrap | update | revoke] [options]\n",
                argv[0]);
            OPT_help(cmp_opts, bio_stdout);
            goto err;
        }
    }

    if (!OPT_init(cmp_opts))
        return EXIT_FAILURE;
    for (i = 1; i < argc; i++) {
        if (*argv[i] == '-') {
            if (strcmp(argv[i], "-section") == 0)
                opt_section = argv[++i];
            else if (strcmp(argv[i], "-config") == 0)
                opt_config = argv[++i];
        }
    }

    if (opt_config[0] == '\0')
        opt_config = CONFIG_DEFAULT;
    LOG(FL_INFO, "Using CMP configuration from '%s'", opt_config);

    if (opt_section[0] == '\0')
        opt_section = DEFAULT_SECTION;
    if (use_case != no_use_case) {
        char *demo_section;

        switch (use_case) {
        case bootstrap:
            demo_section = "bootstrap";
            break;
        case imprint:
            demo_section = "imprint";
            break;
        case update:
            demo_section = "update";
            break;
        case revocation:
            demo_section = "revoke";
            break;
        default:
            return EXIT_FAILURE;
        }
        snprintf(demo_sections, sizeof(demo_sections), "%s,%s", demo_section, opt_section);
        opt_section = demo_sections;
    }

    LOG(FL_INFO, "Using configuration section(s) '%s'", opt_section);
    if ((config = CONF_load_options(NULL, opt_config, opt_section, cmp_opts)) == NULL)
        return EXIT_FAILURE;
    vpm = X509_VERIFY_PARAM_new();
    if (vpm == 0) {
        LOG(FL_ERR, "Out of memory");
        return EXIT_FAILURE;
    }
    if (!CONF_read_vpm(config, opt_section, vpm))
        return EXIT_FAILURE;

    if (use_case != no_use_case)
        opt_index++; /* skip first option since use_case is given */
    rc = get_opts(argc, argv);
    if (rc == -1) {
        OPT_help(cmp_opts, bio_stdout);
        return EXIT_SUCCESS;
    }
    if (rc == 1)
        return EXIT_FAILURE;

    /* handle here to start correct demo use case */
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
        } else {
            if (strcmp(opt_cmd, "genm") == 0)
                LOG(FL_ERR, "CMP request type '%s' is not supported", opt_cmd);
            else
                LOG(FL_ERR, "Unknown CMP request command '%s'", opt_cmd);
            return EXIT_FAILURE;
        }
    } else if (use_case == no_use_case && opt_cmd == NULL) {
        LOG(FL_ERR, "No use case and no '-cmd' option given. Use -help to show usage.");
        return EXIT_FAILURE;
    }

    if ((rc = CMPclient_demo(use_case)) != CMP_OK)
        goto err;

    if (sec_deinit(sec_ctx) == -1)
        return EXIT_FAILURE;

#if OPENSSL_VERSION_NUMBER >= 0x10100002L
# ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks_fp(stderr) <= 0)
        rc = EXIT_FAILURE;
# endif
#endif

 err:
    return rc > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
