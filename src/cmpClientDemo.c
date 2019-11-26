/*!*****************************************************************************
 * @file   cmpClientDemo.c
 * @brief  generic CMP client library detailed usage demonstration
 *
 * @author David von Oheimb, CT RDA CST SEA, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2018-2019 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 *  SPDX-License-Identifier: Apache-2.0
 ******************************************************************************/

#include <string.h>

#include <securityUtilities.h>
#include <SecUtils/config/config.h>

#include <genericCMPClient.h>

#include <openssl/ssl.h>

/* needed for OSSL_CMP_ITAV_gen() in function CMPclient_demo() */
#include "../cmpossl/crypto/cmp/cmp_local.h"

#define CONFIG_DEFAULT "config/demo.cnf"
#define DEFAULT_SECTION "default"

#ifdef LOCAL_DEFS
X509 *CREDENTIALS_get_cert(const CREDENTIALS *creds);
#endif

enum use_case { imprint, bootstrap, update,
                revocation /* 'revoke' already defined in unistd.h */ };

#define RSA_SPEC "RSA:2048"
#define ECC_SPEC "EC:prime256v1"

/* Option states */
static int opt_index = 2;   /* starting at 2 parses first option after 'use_case' option */
static char *arg;

char *prog = NULL;

    char *opt_server = NULL;            /* 'ADDRESS[:PORT]' of the CMP server. Port defaults to 8080 */
    char *opt_proxy = NULL;             /* 'ADDRESS[:PORT]' of HTTP proxy to the CMP server. Default port 8080 */
    int  opt_msgtimeout = -1;          /* Timeout per CMP message round trip (or 0 for none). Default 120 seconds */
    int  opt_totaltimeout = -1;        /* Overall time an enrollment incl. polling may take. Default: 0 = infinite */

    char *opt_path = NULL;              /* HTTP path (aka CMP alias) inside the CMP server */
    char *opt_cmd_s = NULL;             /* CMP command to execute: 'ir'/'cr'/'p10cr'/'kur'/'rr' */
    int   opt_cmd = 0;

    char *opt_ref = NULL;               /* Reference value to use as senderKID in case no -cert is given */
    char *opt_secret = NULL;            /* Secret value for authentication with a pre-shared key (PBM) */

    char *opt_creds = NULL;             /* cid determining file to read client credentials for CMP-level authentication */
    char *opt_cert = NULL;              /* (legacy option) Client current certificate (plus any extra certs) */
    char *opt_key = NULL;               /* (legacy option) Key for the client's current certificate */
    char *opt_keypass = NULL;           /* (legacy option) Password for the client's key */

    char *opt_oldcert = NULL;           /* cid determining certificate to be to be renewed in KUR or revoked in RR */
    X509 *old_cert = NULL;
    char *opt_csr = NULL;               /* File to read CSR from for P10CR (for legacy support) */
    int  opt_revreason = CRL_REASON_NONE; /* Reason code to be included in revocation request (RR). Values: -1..6, 8..10. None set by default */

    bool  opt_tls_used = false;         /* Flag for forced activation of TLS */
    char *opt_tls_trusted = NULL;       /* component ID to use for getting trusted TLS certificates (trust anchor) */
    char *opt_tls_host = NULL;          /* TLS server's address (host name or IP address) to be checked */
    char *opt_tls_extra = NULL;         /* Extra certificates to provide to TLS server during TLS handshake */
    char *opt_tls_cert = NULL;          /* (legacy option) Client certificate (plus any extra certs) for TLS connection */
    char *opt_tls_key = NULL;           /* (legacy option) Client key for TLS connection */
    char *opt_tls_keypass = NULL;       /* (legacy option) Client key password for TLS connection */

    char *opt_newkey = NULL;            /* File (in PEM format) of key to use for the old/new certificate */
    char *opt_newkeypass = NULL;        /* if starts with "engine:", engine holding new key, else password for new key file */
    char *opt_extracertsout = NULL;     /* File to save extra certificates received */
    char *opt_cacertsout = NULL;        /* File where to save received CA certificates (from IR) */
    char *opt_certout = NULL;           /* cid determining file where to save the received certificate */
    char *opt_out_trusted = NULL;       /* File of trusted certificates for verifying the enrolled cert */
    X509_STORE *out_trusted_ts = NULL;  /* Trusted certificates for verifying the enrolled cert */

    char *opt_srvcert = NULL;           /* Server certificate directly trusted for CMP signing */
    char *opt_trusted = NULL;           /* cid to use for getting trusted CMP certificates (trust anchor) */
    char *opt_untrusted = NULL;         /* File(s) with untrusted certificates for TLS, CMP, and CA */
    bool opt_ignore_keyusage = false;   /* Workaround for CMP server cert without 'digitalSignature' key usage*/
    char *opt_crls_url = NULL;          /* Use given URL as (primary) CRL source when verifying certs. */
    char *opt_crls_file = NULL;         /* Use given local file(s) as (primary) CRL source */
    bool opt_crls_use_cdp = false;      /* Retrieve CRLs from CDPs given in certs as secondary (fallback) source */
    char *opt_cdp_url = NULL;           /* Use given URL(s) ad secondary CRL source */
#ifndef OPENSSL_NO_OCSP
    char *opt_ocsp_url = NULL;          /* Use OCSP with given URL as primary address of OCSP responder */
#endif

    char *opt_extracerts = NULL;        /* File(s) with certificates to append in outgoing messages */
    char *opt_issuer = NULL;            /* X509 Name of the issuer */
    char *opt_recipient = NULL;         /* X509 Name of the recipient */
    char *opt_expect_sender = NULL;     /* X509 Name of the expected sender (CMP server) */
    char *opt_subject = NULL;           /* X509 subject name to be used in the requested certificate template */
    int opt_days = 0;                   /* requested validity time of new cert */
    char *opt_reqexts = NULL;           /* Name of section in the config file defining request extensions */

    char *opt_sans = NULL;              /* List of (critical) Subject Alternative Names (DNS/IPADDR) to be added */
    int opt_san_nodefault = 0;          /* Do not take default SANs from reference certificate (see -oldcert) */
    char *opt_policies = NULL;          /* Policy OID(s) to add as certificate policies request extension */
    int opt_policies_critical = 0;      /* Flag the policies given with -policies as critical */
    char *opt_key_usages = NULL;        /* List of (critical) Basic Key Usages to be added to request exts */
    char *opt_ekus = NULL;              /* List of (critical) Extended Key Usages to be added to request exts */
    int  opt_popo = 1;                  /* Proof-of-Possession (POPO) method */
    char *opt_digest = NULL;            /* Digest-Algorithem for the CMP Signature */
    char *opt_mac = NULL;               /* MAC algorithm to use in PBM-based message protection */

    bool opt_implicitconfirm = false;   /* Request implicit confirmation of enrolled cert */
    bool opt_disableconfirm = false;    /* Do not confirm enrolled certificates */
    bool opt_unprotectedrequests = false; /* Send messages without CMP-level protection */
    bool opt_unprotectederrors = false; /* Allow negative CMP responses to be not protected */

    char *opt_geninfo = NULL;

    char *opt_newkeytype = NULL;        /* specifies keytype e.g. "ECC" or "RSA" */
    char *use_case = NULL;              /* implies section in OpenSSL config file */
    char *configfile = CONFIG_DEFAULT;/* OpenSSL-style configuration file */
    CONF *config = NULL;                /* configuration structure */
    char *sections = DEFAULT_SECTION;   /* sections of config file*/
    X509_VERIFY_PARAM *vpm = NULL;
    CREDENTIALS *creds = NULL;
    X509_STORE *tls_ts = NULL;
    X509_STORE *cmp_ts = NULL;
    OSSL_CMP_CTX *cmp_ctx = NULL;
    SSL_CTX *ssl_ctx = NULL;


/*******************************************************************
 * Table of configuration options
 ******************************************************************/
opt_t cmp_opts[] = {
    { "server", OPT_TXT, { &opt_server } },
    { "proxy", OPT_TXT, { &opt_proxy } },
    { "path", OPT_TXT, { &opt_path } },
    { "msgtimeout", OPT_NUM, { (char **)&opt_msgtimeout } },
    { "totaltimeout", OPT_NUM, { (char **)&opt_totaltimeout} },

    { "recipient", OPT_TXT, { &opt_recipient } },
    { "expect_sender", OPT_TXT, { &opt_expect_sender } },
    { "srvcert", OPT_TXT, { &(opt_srvcert) } },
    { "trusted", OPT_TXT, { &opt_trusted } },
    { "untrusted", OPT_TXT, { &opt_untrusted } },
    { "ignore_keyusage", OPT_NUM, { (char **)&opt_ignore_keyusage } },

    { "ref", OPT_TXT, { &(opt_ref) } },
    { "secret", OPT_TXT, { &(opt_secret) } },
    { "creds", OPT_TXT, { &(opt_creds) } },
    { "cert", OPT_TXT, { &(opt_cert) } },
    { "key", OPT_TXT, { &(opt_key) } },
    { "keypass", OPT_TXT, { &(opt_keypass) } },
    { "extracerts", OPT_TXT, { &opt_extracerts } },

    { "cmd", OPT_TXT, { &(opt_cmd_s) } },
    { "digest", OPT_TXT, { &opt_digest } },
    { "mac", OPT_TXT, { &opt_mac}},
    { "unprotectedrequests", OPT_BOOL, { (char **) &opt_unprotectedrequests } },
    { "unprotectederrors", OPT_BOOL, { (char **) &opt_unprotectederrors } },
    { "extracertsout", OPT_TXT, { &opt_extracertsout } },
    { "cacertsout", OPT_TXT, { &opt_cacertsout } },

    { "newkey", OPT_TXT, { &opt_newkey } },
    { "newkeypass", OPT_TXT, { &opt_newkeypass } },
    { "newkeytype", OPT_TXT, { &opt_newkeytype } },
    { "subject", OPT_TXT, { &opt_subject } },
    { "issuer", OPT_TXT, { &opt_issuer } },
    { "days", OPT_NUM, { (char **) &opt_days } },
    { "reqexts", OPT_TXT, { &opt_reqexts } },

    { "sans", OPT_TXT, { &opt_sans } },
    { "san_nodefault", OPT_BOOL, { (char**) &opt_san_nodefault} },
    { "policies", OPT_TXT, { &opt_policies} },
    { "policies_critical", OPT_BOOL, { (char**) &opt_policies_critical} },
    { "key_usages", OPT_TXT, { &opt_key_usages } },
    { "ekus", OPT_TXT, { &opt_ekus } },
    { "popo", OPT_NUM, { (char **) &opt_popo } },
    { "implicitconfirm", OPT_BOOL, { (char **) &opt_implicitconfirm } },
    { "disableconfirm", OPT_BOOL, { (char **) &opt_disableconfirm } },
    { "certout", OPT_TXT, { &opt_certout } },
    { "out_trusted", OPT_TXT, { &opt_out_trusted } },

    { "oldcert", OPT_TXT, { &opt_oldcert } },
    { "csr", OPT_TXT, { &opt_csr } },
    { "revreason", OPT_NUM, { (char **) &opt_revreason } },

    { "tls_used", OPT_BOOL, { (char **) &opt_tls_used } },
    { "tls_extra", OPT_TXT, { &(opt_tls_extra) } },
    { "tls_cert", OPT_TXT, { &(opt_tls_cert) } },
    { "tls_key", OPT_TXT, { &(opt_tls_key) } },
    { "tls_keypass", OPT_TXT, { &opt_tls_keypass } },

    { "tls_trusted", OPT_TXT, { &(opt_tls_trusted) } },
    { "tls_host", OPT_TXT, { &opt_tls_host } },

    /* TODO add more CRLs and OCSP options for TLS and CMP when support available */
    { "crls_url", OPT_TXT, {&opt_crls_url} },
    { "crls_file", OPT_TXT, {&opt_crls_file} },
    { "crls_use_cdp", OPT_BOOL, { (char **) &opt_crls_use_cdp } },
    { "cdp_url", OPT_TXT, {&opt_cdp_url} },
#ifndef OPENSSL_NO_OCSP
    { "ocsp_url", OPT_TXT, {&opt_ocsp_url} },
#endif

    { "geninfo", OPT_TXT, { &opt_geninfo } },

    { NULL, OPT_TXT, { NULL } }
};

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_SERVER = 0, OPT_PROXY, OPT_PATH,
    OPT_MSGTIMEOUT, OPT_TOTALTIMEOUT,

    OPT_RECIPIENT, OPT_EXPECT_SENDER, OPT_SRVCERT, OPT_TRUSTED,
    OPT_UNTRUSTED, OPT_IGNORE_KEYUSAGE,

    OPT_REF, OPT_SECRET, OPT_CREDS, OPT_CERT,
    OPT_KEY, OPT_KEYPASS, OPT_EXTRACERTS,

    OPT_CMD_S, OPT_DIGEST, OPT_MAC, OPT_UNPROTECTEDREQUESTS,
    OPT_UNPROTECTEDERRORS, OPT_EXTRACERTSOUT, OPT_CACERTSOUT,

    OPT_NEWKEY, OPT_NEWKEYPASS, OPT_NEWKEYTYPE, OPT_SUBJECT,
    OPT_ISSUER, OPT_DAYS, OPT_REQEXTS,

    OPT_SANS, OPT_SAN_NODEFAULT, OPT_POLICIES, OPT_POLICIES_CRITICAL,
    OPT_KEY_USAGES, OPT_EKUS, OPT_POPO, OPT_IMPLICITCONFIRM,
    OPT_DISABLECONFIRM, OPT_CERTOUT, OPT_OUT_TRUSTED,

    OPT_OLDCERT, OPT_CSR, OPT_REVREASON,

    OPT_TLS_USED, OPT_TLS_EXTRA, OPT_TLS_CERT, OPT_TLS_KEY,
    OPT_TLS_KEYPASS,

    OPT_TLS_TRUSTED, OPT_TLS_HOST,

    OPT_CRLS_URL, OPT_CRLS_FILE, OPT_CRLS_USE_CDP, OPT_CDP_URL,
#ifndef OPENSSL_NO_OCSP
    OPT_OCSP_URL,
#endif

    OPT_GENINFO,

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
                                               sk_X509_value(certs, i));
    }
    sk_X509_free(certs); /* must not free the stack elements */
    if (res == 0)
        LOG(FL_ERR, "error: unable to use TLS extra certs\n");
    return res;
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

#if 0
    const char *crls_files = opt_crls_file;
    crls = CRLs_load(crls_files, "CRLs for TLS level");
    if (crls == NULL)
        goto err;
#endif
    const X509_VERIFY_PARAM *vpm = NULL;
    const bool full_chain = true;
    const bool use_CDPs = false;
    const char *CRLs_url = NULL; /* or: opt_crls_url */
    const bool use_AIAs = true;
    const char *OCSP_url = opt_ocsp_url;
    const bool try_stapling = (use_AIAs || OCSP_url != NULL) && OPENSSL_VERSION_NUMBER >= 0x1010001fL;
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
    /* TODO maybe also add untrusted certs to help building chain of TLS client and checking stapled OCSP responses */
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

    crls = CRLs_load(crls_files, "CRLs for CMP level");
    if (crls == NULL)
        goto err;

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

X509_EXTENSIONS *setup_X509_extensions(void)
{
    X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();
    X509V3_CTX ext_ctx;

    if (exts == NULL)
        return NULL;
    if ((opt_reqexts != NULL) || (opt_policies != NULL)) {
        X509V3_set_ctx(&ext_ctx, NULL, NULL, NULL, NULL, 0);
        X509V3_set_nconf(&ext_ctx, config);
    }

    if (opt_reqexts != NULL) {
        if (!X509V3_EXT_add_nconf_sk(config, &ext_ctx, opt_reqexts, &exts)) {
            LOG(FL_ERR, "cannot load extension section '%s'", opt_reqexts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            return NULL;
        }
    }

    if (opt_policies != NULL) {
        if (!X509V3_EXT_add_nconf_sk(config, &ext_ctx, opt_policies, &exts)) {
            LOG(FL_ERR, "cannot load policy section '%s'", opt_policies);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            return NULL;
        }
    }

    return exts;
}

CMP_err prepare_CMP_client(CMP_CTX **pctx, OPTIONAL OSSL_cmp_log_cb_t log_fn,
                           OPTIONAL CREDENTIALS *cmp_creds)
{
    X509_STORE *cmp_truststore = setup_CMP_truststore();
    if (cmp_truststore == NULL)
        return -1;
    STACK_OF(X509) *untrusted_certs = opt_untrusted == NULL ? NULL :
        CERTS_load(opt_untrusted, "untrusted certs for CMP");

    const char *new_cert_trusted = opt_out_trusted == NULL ? opt_srvcert : opt_out_trusted;
    LOG(FL_INFO, "Using '%s' as cert truststore for verifying new cert",
            opt_out_trusted == NULL ? opt_srvcert : opt_out_trusted);
    X509_STORE *new_cert_truststore =
        STORE_load(new_cert_trusted, "trusted certs for verifying new cert");
    CMP_err err = -2;
    if (new_cert_truststore == NULL)
        goto err;
    /* no revocation done for newly enrolled cert */

    OSSL_cmp_transfer_cb_t transfer_fn = NULL; /* default HTTP(S) transfer */
    const bool implicit_confirm = opt_implicitconfirm;
    err = CMPclient_prepare(pctx, log_fn,
                            cmp_truststore, opt_recipient,
                            untrusted_certs,
                            cmp_creds, opt_digest, opt_mac,
                            transfer_fn, opt_totaltimeout,
                            new_cert_truststore, implicit_confirm);
    CERTS_free(untrusted_certs);
    STORE_free(new_cert_truststore);
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
            LOG(FL_ERR, "out of memory\n");
            return 0;
        }
        GENERAL_NAME_free(n);
    }
    return 1;
}

/*
 * return OPTION_choice index on success, -1 if options does not match and
 * OPT_END if all options are handled
 */
static int opt_next(int argc, char **argv){
    int i;
    char *param;

 retry:
    /* Look at current arg; at end of the list? */
    arg = NULL;
    param = argv[opt_index];
    if (param == NULL)
        return OPT_END;

    /* If word doesn't start with a -, we're done. */
    if (*param != '-')
        return OPT_END;

    /* if starting with '-', snip it of */
    if (*param == '-')
        param++;

    opt_index++;
    for (i = 0; i < OPT_END; i++) {
        /* already handled, check next option*/
        if (!strcmp(param, "sections") || !strcmp(param, "configfile")) {
            opt_index++;
            goto retry;
        }
        if (!strcmp(param, cmp_opts[i].name)) {
            arg = argv[opt_index];
            opt_index++;
            return i;
        }
    }

    if (opt_index == argc)
        return OPT_END;

    /* in case of unknown option, return option with leading '-' */
    arg = --param;
    return OPT_ERR;
}

static int get_opts(int argc, char **argv)
{
    OPTION_CHOICE o;
    int res;

    while ((o = opt_next(argc, argv)) != OPT_END) {
        if (o == OPT_ERR) {
            LOG(FL_ERR, "Unknown option '%s' used", arg);
            return 0;
        }

        switch (cmp_opts[o].type) {
        case OPT_TXT:
            *cmp_opts[o].varref_u.txt = arg;
            break;
        case OPT_NUM:
            if ((*cmp_opts[o].varref_u.num = UTIL_atoint(arg)) == INT_MIN) {
                LOG(FL_ERR, "Can't parse '%s' as number", arg);
                return 0;
            }
            break;
        case OPT_BOOL:
            res = UTIL_atoint(arg);
            if (res == 0 || res == 1) {
                *cmp_opts[o].varref_u.bool = UTIL_atoint(arg);
            } else {
                LOG(FL_ERR, "Can't parse '%s' as bool", arg);
                return 0;
            }
            break;
        default:
            return 0;
        }
    }
    return 1;
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
        use_case == imprint ? CREDENTIALS_new(NULL, NULL, NULL, opt_secret, opt_ref) :
        use_case == bootstrap ? CREDENTIALS_load(opt_cert, opt_key, opt_keypass, creds_desc)
                              : CREDENTIALS_load(opt_certout, opt_newkey, opt_newkeypass, creds_desc);
    if (cmp_creds == NULL) {
        err = -4;
        goto err;
    }

    err = prepare_CMP_client(&ctx, log_fn, cmp_creds);
    if (err != CMP_OK) {
        goto err;
    }

    if (opt_issuer != NULL) {
        X509_NAME *n = UTIL_parse_name(opt_issuer, MBSTRING_ASC, 0);
        if (n == NULL) {
            LOG(FL_ERR, "cannot parse issuer DN '%s'", opt_issuer);
            goto err;
        }
        if (!OSSL_CMP_CTX_set1_issuer(ctx, n)) {
            X509_NAME_free(n);
            LOG(FL_ERR, "out of memory");
            goto err;
        }
        X509_NAME_free(n);
    }

    if (opt_expect_sender != NULL) {
        X509_NAME *n = UTIL_parse_name(opt_expect_sender, MBSTRING_ASC, 0);
        if (n == NULL) {
            LOG(FL_ERR, "cannot parse expected sender DN '%s'", opt_expect_sender);
            err = -5;
            goto err;
        }
        if (!OSSL_CMP_CTX_set1_expected_sender(ctx, n)) {
            X509_NAME_free(n);
            LOG(FL_ERR, "out of memory");
            err = -6;
            goto err;
        }
        X509_NAME_free(n);
    }

    if (opt_extracerts != NULL) {
        STACK_OF(X509) *certs = CERTS_load(opt_extracerts, "extra certificates for CMP");
        if (certs == NULL) {
            err = -5;
            goto err;
        } else {
            if (!OSSL_CMP_CTX_set1_extraCertsOut(ctx, certs)){
                err = -6;
                sk_X509_pop_free(certs, X509_free);
                goto err;
            }
            sk_X509_pop_free(certs, X509_free);
        }
    }

    /* direct call of CMP API */
    if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_ERRORS, opt_unprotectederrors)
            || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IGNORE_KEYUSAGE, opt_ignore_keyusage)
            || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_VALIDITYDAYS, opt_days)
            || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_POPOMETHOD, opt_popo)
            || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DISABLECONFIRM, opt_disableconfirm)
            || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_SEND, opt_unprotectedrequests)) {
        err = CMP_R_INVALID_ARGS;
        goto err;
    }

    if (opt_san_nodefault) {
        if (opt_sans != NULL)
            LOG(FL_ERR, "-opt_san_nodefault has no effect when -sans is used\n");
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT, 1)) {
            err = CMP_R_INVALID_ARGS;
            goto err;
        }
    }

    if (opt_policies_critical) {
        if (opt_policies == NULL)
            LOG(FL_ERR, "-opt_policies_critical has no effect unless -policies is given\n");
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_POLICIES_CRITICAL, 1)) {
            err = CMP_R_INVALID_ARGS;
            goto err;
        }
    }

    if (opt_tls_used && (tls = setup_TLS()) == NULL) {
        err = -7;
        goto err;
    }
    const char *path = opt_path;
    const char *server = opt_tls_used ? opt_tls_host : opt_server;
    err = CMPclient_setup_HTTP(ctx, server, path, opt_msgtimeout, tls, opt_proxy);
#ifndef SEC_NO_TLS
    TLS_free(tls);
#endif
    if (err != CMP_OK) {
        goto err;
    }

    if (use_case != revocation) {
        const char *key_spec = !strcmp(opt_newkeytype, "RSA") ? RSA_SPEC : ECC_SPEC;
        new_pkey = KEY_new(key_spec);
        if (new_pkey == NULL) {
            err = -8;
            goto err;
        }
    }

    if ((use_case == imprint || use_case == bootstrap)
        && (exts = setup_X509_extensions()) == NULL) {
        err = -9;
        goto err;
    }

    if (reqExtensions_have_SAN(exts) && opt_sans != NULL) {
        LOG(FL_ERR, "Cannot have Subject Alternative Names both via -reqexts and via -sans\n");
        err = CMP_R_MULTIPLE_SAN_SOURCES;
        goto err;
    }

    if (!set_gennames(ctx, opt_sans, "Subject Alternative Name")){
        err = -10;
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
        if (aint == NULL || !ASN1_INTEGER_set(aint, value))
            goto err;

        val = ASN1_TYPE_new();
        if (val == NULL) {
            ASN1_INTEGER_free(aint);
            goto err;
        }
        ASN1_TYPE_set(val, V_ASN1_INTEGER, aint);
        itav = OSSL_CMP_ITAV_gen(type, val);
        if (itav == NULL) {
            ASN1_TYPE_free(val);
            goto err;
        }

        if (!OSSL_CMP_CTX_push0_geninfo_ITAV(ctx, itav)) {
            OSSL_CMP_ITAV_free(itav);
            goto err;
        }
    }

    switch (use_case) {
    case imprint:
        err = CMPclient_imprint(ctx, &new_creds, new_pkey, opt_subject, exts);
        break;
    case bootstrap:
        err = CMPclient_bootstrap(ctx, &new_creds, new_pkey, opt_subject, exts);
        break;
    case update:
        err = CMPclient_update(ctx, &new_creds, new_pkey);
        break;
    case revocation:
        err = CMPclient_revoke(ctx, CREDENTIALS_get_cert(cmp_creds), opt_revreason);
        /* CmpWsRa does not accept CRL_REASON_NONE: "missing crlEntryDetails for REVOCATION_REQ" */
        break;
    default:
        err = -11;
    }
    if (err != CMP_OK) {
        goto err;
    }

    if (opt_cacertsout != NULL) {
        sec_file_format format = FILES_get_format(opt_cacertsout);
        STACK_OF(X509) *certs = OSSL_CMP_CTX_get1_caPubs(cmp_ctx);
        if (format == FORMAT_UNDEF) {
            err = -12;
            goto err;
        }
        if (sk_X509_num(certs) > 0
                && FILES_store_certs(certs, opt_cacertsout, format, "CA") < 0) {
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    if (opt_extracertsout != NULL) {
        sec_file_format format = FILES_get_format(opt_extracertsout);
        STACK_OF(X509) *certs = OSSL_CMP_CTX_get1_extraCertsIn(cmp_ctx);
        if (format == FORMAT_UNDEF) {
            err = -13;
            goto err;
        }
        if (sk_X509_num(certs) > 0
                && FILES_store_certs(certs, opt_extracertsout, format, "extra") < 0) {
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    if (use_case != revocation) {
        const char *new_desc = "newly enrolled certificate and related key and chain";
        if (!CREDENTIALS_save(new_creds, opt_certout, opt_newkey, opt_newkeypass, new_desc)) {
            err = -12;
            goto err;
        }
    }

 err:
    CMPclient_finish(ctx); /* this also frees ctx */
    KEY_free(new_pkey);
    EXTENSIONS_free(exts);
    CREDENTIALS_free(new_creds);
    CREDENTIALS_free(cmp_creds);

    LOG_close(); /* not really needed since done also in sec_deinit() */
    if (err != CMP_OK) {
        LOG(FL_ERR, "CMPclient error %d\n", err);
    }
    return err;
}

int main(int argc, char *argv[])
{
    int i;

#if OPENSSL_VERSION_NUMBER >= 0x10100002L
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    char *p = getenv("OPENSSL_DEBUG_MEMORY");
    if (p != NULL && strcmp(p, "on") == 0)
        CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
#endif

    sec_ctx *sec_ctx = sec_init();
    if (sec_ctx == NULL) {
        LOG(FL_ERR, "failure getting SecUtils ctx");
        return EXIT_FAILURE;
    }

    enum use_case use_case = bootstrap; /* default */
    if (argc > 1) {
        if (!strcmp(argv[1], "imprint"))
            use_case = imprint;
        else if (!strcmp(argv[1], "bootstrap"))
            use_case = bootstrap;
        else if (!strcmp(argv[1], "update"))
            use_case = update;
        else if (!strcmp(argv[1], "revoke"))
            use_case = revocation;
        else {
            LOG(FL_ERR, "Usage: %s [imprint | bootstrap | update | revoke]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    for (i = 1; i < argc; i++) {
        if (*argv[i] == '-') {
            if (!strcmp(argv[i], "-sections"))
                sections = argv[i +1];
            else if (!strcmp(argv[i], "-config"))
                configfile = argv[i + 1];
        }
    }

    if (sections[0] == '\0')    /* empty string */
        sections = DEFAULT_SECTION;
    if (configfile[0] == '\0')  /* empty string */
        configfile = CONFIG_DEFAULT;

    LOG(FL_INFO, "Using CMP configuration from '%s'", configfile);

    switch(use_case) {
    case bootstrap:
        if ((config =CONF_load_options(NULL, configfile, "bootstrap,default", &cmp_opts[0])) == 0)
            return EXIT_FAILURE;
        break;
    case imprint:
        if ((config = CONF_load_options(NULL, configfile, "imprint,default", &cmp_opts[0])) == 0)
            return EXIT_FAILURE;
        break;
    case update:
        if ((config = CONF_load_options(NULL, configfile, "update,default", &cmp_opts[0])) == 0)
            return EXIT_FAILURE;
        break;
    case revocation:
        if ((config = CONF_load_options(NULL, configfile, "revoke,default", &cmp_opts[0])) == 0)
            return EXIT_FAILURE;
        break;
    default:
        return EXIT_FAILURE;
    }
    if (!CONF_read_options(config, sections, &cmp_opts[0]))
        return EXIT_FAILURE;

    vpm = X509_VERIFY_PARAM_new();
    if (vpm == 0) {
        LOG(FL_ERR, "Out of memory");
        return EXIT_FAILURE;
    }
    if (!CONF_read_vpm(config, sections, vpm))
        return EXIT_FAILURE;

    if (!get_opts(argc, argv))
        return EXIT_FAILURE;

    int rc = CMPclient_demo(use_case) == CMP_OK ? EXIT_SUCCESS : EXIT_FAILURE;

    if (sec_deinit(sec_ctx) < 0) {
        rc = EXIT_FAILURE;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100002L
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks_fp(stderr) <= 0)
        rc = EXIT_FAILURE;
#endif
#endif
    return rc;
}
