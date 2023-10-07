/*-
 * @file   cmpClient.c
 * @brief  generic CMP client library demo/test client
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
 *  Copyright Nokia 2007-2019
 *  Copyright (c) 2015-2023 Siemens AG
 *
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

#include <genericCMPClient.h>

#include <openssl/ssl.h>

#include <secutils/config/config.h>
#include <secutils/credentials/cert.h>
#include <secutils/credentials/verify.h>
#include <secutils/certstatus/crl_mgmt.h> /* for CRLMGMT_load_crl_cb */

#ifdef LOCAL_DEFS
# include "genericCMPClient_use.h"
#endif

/*
 * Use cases are split between CMP use cases and others,
 * which do not use CMP and therefore do not need its complex setup.
 */
enum use_case { no_use_case,
                /* CMP use cases: */
                imprint, bootstrap, pkcs10, update,
                revocation /* 'revoke' already defined in unistd.h */, genm,
                default_case,
                /* Non-CMP use cases: */
                validate
};

#define RSA_SPEC "RSA:2048"
#define ECC_SPEC "EC:prime256v1"

#define CONFIG_DEFAULT "config/demo.cnf"
#define CONFIG_TEST "test_config.cnf" /* from OpenSSL test suite */

char *opt_config = CONFIG_DEFAULT; /* OpenSSL-style configuration file */
CONF *config = NULL; /* OpenSSL configuration structure */
char *opt_section = "EJBCA"; /* name(s) of config file section(s) to use */
#define DEFAULT_SECTION "default"
#define SECTION_NAME_MAX 40
char demo_sections[2 * (SECTION_NAME_MAX + 1)]; /* used for pattern "%s,%s" */
long opt_verbosity;

/* message transfer */
const char *opt_server;
const char *opt_proxy;
const char *opt_no_proxy;
const char *opt_path;
const char *opt_cdp_proxy;
const char *opt_crl_cache_dir;

long opt_keep_alive;
long opt_msg_timeout;
long opt_total_timeout;

/* server authentication */
const char *opt_trusted;
const char *opt_untrusted;
const char *opt_srvcert;
const char *opt_recipient;
const char *opt_expect_sender;
bool opt_ignore_keyusage;
bool opt_unprotected_errors;
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
bool opt_no_cache_extracerts;
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30200000L || defined USE_LIBCMP
const char *opt_srvcertout;
#endif
const char *opt_extracertsout;
const char *opt_extracerts_dir;
const char *opt_extracerts_dir_format;
const char *opt_cacertsout;
const char *opt_cacerts_dir;
const char *opt_cacerts_dir_format;
const char *opt_oldwithold;
const char *opt_newwithnew;
const char *opt_newwithold;
const char *opt_oldwithnew;
const char *opt_template;
const char *opt_oldcrl;
const char *opt_crlout;

/* client authentication */
const char *opt_ref;
const char *opt_secret;
/* maybe it would be worth re-adding a -creds option combining -cert and -key */
const char *opt_cert;
const char *opt_own_trusted;
const char *opt_key;
const char *opt_keypass;
const char *opt_digest;
const char *opt_mac;
const char *opt_extracerts;
bool opt_unprotected_requests;

/* generic message */
const char *opt_cmd;
const char *opt_infotype;
static int infotype = NID_undef;
const char *opt_profile;
char *opt_geninfo;

/* certificate enrollment */
const char *opt_newkeytype;
bool opt_centralkeygen;
const char *opt_newkey;
const char *opt_newkeypass;
const char *opt_subject;
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

/* certificate enrollment and revocation */
const char *opt_oldcert;
long opt_revreason;
const char *opt_issuer;
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
char *opt_serial;
#endif

/* TODO? add credentials format options */
/* TODO add opt_engine */

/* TLS connection */
bool opt_tls_used;
/* TODO re-add tls_creds */
const char *opt_tls_cert;
const char *opt_tls_key;
const char *opt_tls_keypass;
const char *opt_tls_extra;
const char *opt_tls_trusted;
const char *opt_tls_host;

/* client-side debugging */
static char *opt_reqin = NULL;
static bool opt_reqin_new_tid = 0;
static char *opt_reqout = NULL;
static char *opt_rspin = NULL;
static char *opt_rspout = NULL;

/* TODO further extend verification options and align with OpenSSL:apps/cmp.c */
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
CRLMGMT_DATA *cmdata = NULL;
STACK_OF(X509_CRL) *crls = NULL;

opt_t cmp_opts[] = {
    { "help", OPT_BOOL, {.num = -1}, { NULL },
      "Display this summary"},
    { "config", OPT_TXT, {.txt = NULL}, { NULL },
      "Configuration file to use. \"\" means none. Default 'config/demo.cnf'"},
    { "section", OPT_TXT, {.txt = NULL}, { NULL },
      "Section(s) in config file to use. \"\" means 'default'. Default 'EJBCA'"},
    { "verbosity", OPT_NUM, {.num = LOG_INFO}, {(const char **) &opt_verbosity},
      "Logging level; 3=ERR, 4=WARN, 6=INFO, 7=DEBUG, 8=TRACE. Default 6 = INFO"},

    OPT_HEADER("Generic message"),
    { "cmd", OPT_TXT, {.txt = NULL}, { &opt_cmd },
      "CMP request to send: ir/cr/p10cr/kur/rr/genm. Overrides 'use_case' if given"},
    { "infotype", OPT_TXT, {.txt = NULL}, { &opt_infotype },
      "InfoType name for requesting specific info in genm, "
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
      "with specific support"
#else
      "e.g., C<signKeyPairTypes>"
#endif
    },
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    OPT_MORE("for 'caCerts', 'rootCaCert', 'certReqTemplate', and 'crlStatusList'"),
#endif
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    { "profile", OPT_TXT, {.txt = NULL}, { &opt_profile },
      "Cert profile name to place in generalInfo field of PKIHeader of requests"},
#endif
    { "geninfo", OPT_TXT, {.txt = NULL}, { (const char **)&opt_geninfo },
      "Comma-separated list of OID and value to place in generalInfo PKIHeader"},
    OPT_MORE("of form <OID>:int:<n> or <OID>:str:<s>, e.g. \'1.2.3.4:int:56789, id-kp:str:name'"),
    { "template", OPT_TXT, {.txt = NULL}, { &opt_template },
      "File to save certTemplate received in genp of type certReqTemplate"},

    OPT_HEADER("Certificate enrollment"),
    { "newkeytype", OPT_TXT, {.txt = NULL}, { &opt_newkeytype },
      "Generate or request key for ir/cr/kur of given type, e.g., EC:secp521r1"},
    { "centralkeygen", OPT_BOOL, {.bit = false},
      { (const char **) &opt_centralkeygen},
      "Request central (server-side) key generation. Default is local generation"},
    { "newkey", OPT_TXT, {.txt = NULL}, { &opt_newkey },
      "Private or public key for for ir/cr/kur (defaulting to pubkey of -csr) if -newkeytype not given."},
    OPT_MORE("File to save new key if -newkeytype is given"),
    { "newkeypass", OPT_TXT, {.txt = NULL}, { &opt_newkeypass },
      "Pass phrase source for -newkey"},
    { "subject", OPT_TXT, {.txt = NULL}, { &opt_subject },
      "Distinguished Name (DN) of subject to use in the requested cert template"},
    OPT_MORE("For kur, default is subject of -csr arg, else subject of -oldcert"),
    { "days", OPT_NUM, {.num = 0}, { (const char **) &opt_days },
      "Requested validity time of new cert in number of days"},
    { "reqexts", OPT_TXT, {.txt = NULL}, { &opt_reqexts },
      "Name of config file section defining certificate request extensions"},
    OPT_MORE("Augments or replaces any extensions contained CSR given with -csr"),
    { "sans", OPT_TXT, {.txt = NULL}, { (const char **) &opt_sans },
      "Subject Alt Names (IPADDR/DNS/URI) to add as (critical) cert req extension"},
    { "san_nodefault", OPT_BOOL, {.bit = false},
      { (const char **) &opt_san_nodefault},
      "Do not take default SANs from reference certificate (see -oldcert)"},
    { "policies", OPT_TXT, {.txt = NULL}, { &opt_policies},
      "Name of config file section defining policies request extension"},
    { "policy_oids", OPT_TXT, {.txt = NULL}, {(const char **) &opt_policy_oids},
      "Policy OID(s) to add as certificate policies request extension"},
    { "policy_oids_critical", OPT_BOOL, {.bit = false},
      { (const char **) &opt_policy_oids_critical},
      "Flag the policy OID(s) given with -policies_ as critical"},
    { "popo", OPT_NUM, {.num = OSSL_CRMF_POPO_NONE - 1},
      { (const char **) &opt_popo },
      "Proof-of-Possession (POPO) method to use for ir/cr/kur where"},
    OPT_MORE("-1 = NONE, 0 = RAVERIFIED, 1 = SIGNATURE (default), 2 = KEYENC"),
    { "csr", OPT_TXT, {.txt = NULL}, { &opt_csr },
      "CSR file in PKCS#10 format to convert or to use in p10cr"},
    { "out_trusted", OPT_TXT, {.txt = NULL}, { &opt_out_trusted },
      "Certs to trust when validating newly enrolled certs; defaults to -srvcert"},
    { "implicit_confirm", OPT_BOOL, {.bit = false},
      { (const char **) &opt_implicit_confirm },
      "Request implicit confirmation of newly enrolled certificates"},
    { "disable_confirm", OPT_BOOL, {.bit = false},
      { (const char **) &opt_disable_confirm },
      "Do not confirm newly enrolled certificates w/o requesting implicit confirm"},
    { "certout", OPT_TXT, {.txt = NULL}, { &opt_certout },
      "File to save newly enrolled certificate, possibly with chain and key"},
    { "chainout", OPT_TXT, {.txt = NULL}, { &opt_chainout },
      "File to save the chain of the newly enrolled certificate"},

    OPT_HEADER("Certificate enrollment and revocation"),
    { "oldcert", OPT_TXT, {.txt = NULL}, { &opt_oldcert },
      "Certificate to be updated (defaulting to -cert) or to be revoked in rr;"},
    OPT_MORE("also used as reference (defaulting to -cert) for subject DN and SANs."),
    OPT_MORE("Its issuer used as recipient unless -srvcert, -recipient or -issuer given"),
    OPT_MORE("It is also used for CRLSource data in genm of type crlStatusList"),
    { "revreason", OPT_NUM, {.num = CRL_REASON_NONE},
      { (const char **) &opt_revreason },
      "Reason code to include in revocation request (rr)."},
    OPT_MORE("Values: 0..6, 8..10 (see RFC5280, 5.3.1) or -1. Default -1 = none included"),
    { "issuer", OPT_TXT, {.txt = NULL}, { &opt_issuer },
      "DN of the issuer to place in the certificate template of ir/cr/kur"
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
      "/rr"
#else
      ""
#endif
      ";"},
    OPT_MORE("also used as recipient if neither -recipient nor -srvcert are given"),
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    { "serial", OPT_TXT, {.txt = NULL}, {(const char **) &opt_serial},
      "Serial number of certificate to be revoked in revocation request (rr)"},
#endif
    /* Note: Lightweight CMP Profile SimpleLra does not allow CRL_REASON_NONE */

    /* TODO? OPT_HEADER("Credentials format"), */
    /* TODO add opt_engine */

    OPT_HEADER("Message transfer"),
    { "server", OPT_TXT, {.txt = NULL}, { &opt_server },
      "[http[s]://]host[:port][/path] of CMP server. Default port 80 or 443."},
    OPT_MORE("host may be a DNS name or an IP address; path can be overridden by -path"),
    { "proxy", OPT_TXT, {.txt = NULL}, { &opt_proxy },
      "[http[s]://]host[:port][/p] of proxy. Default port 80 or 443; p ignored."},
    OPT_MORE("Default from environment variable 'http_proxy', else 'HTTP_PROXY'"),
    { "no_proxy", OPT_TXT, {.txt = NULL}, { &opt_no_proxy },
      "List of addresses of servers not use HTTP(S) proxy for."},
    OPT_MORE("Default from environment variable 'no_proxy', else 'NO_PROXY', else none"),

    { "recipient", OPT_TXT, {.txt = NULL}, { &opt_recipient },
      "DN of CA. Default: -srvcert subject, -issuer, issuer of -oldcert or -cert,"},
    OPT_MORE("subject of the first -untrusted cert if any, or else the NULL-DN"),
    { "path", OPT_TXT, {.txt = NULL}, { &opt_path },
      "HTTP path (aka CMP alias) at the CMP server.  Default from -server, else \"/\""},
    {"keep_alive", OPT_NUM, {.num = 1 }, { (const char **)&opt_keep_alive },
     "Persistent HTTP connections. 0: no, 1 (the default): request, 2: require"},
    { "msg_timeout", OPT_NUM, {.num = 120}, { (const char **)&opt_msg_timeout },
      "Timeout per CMP message round trip (or 0 for none). Default 120 seconds"},
    { "total_timeout", OPT_NUM, {.num = 0}, {(const char **)&opt_total_timeout},
      "Overall time an enrollment incl. polling may take. Default: 0 = infinite"},

    OPT_HEADER("Server authentication"),
    { "trusted", OPT_TXT, {.txt = NULL}, { &opt_trusted },
      "Certificates to use as trust anchors when validating signed CMP responses"},
    { "untrusted", OPT_TXT, {.txt = NULL}, { &opt_untrusted },
      "Intermediate CA certs for chain construction for CMP/TLS/enrolled certs"},
    { "srvcert", OPT_TXT, {.txt = NULL}, { &opt_srvcert },
      "Server cert to pin and trust directly when validating signed CMP responses"},
    { "expect_sender", OPT_TXT, {.txt = NULL}, { &opt_expect_sender },
      "DN of expected sender of responses. Defaults to subject of -srvcert, if any"},
    { "ignore_keyusage", OPT_BOOL, {.bit = false},
      { (const char **)&opt_ignore_keyusage },
      "Ignore CMP signer cert key usage, else 'digitalSignature' must be allowed"},
    { "unprotected_errors", OPT_BOOL, {.bit = false},
      { (const char **) &opt_unprotected_errors },
      "Accept missing or invalid protection of regular error messages and negative"},
    OPT_MORE("certificate responses (ip/cp/kup), revocation responses (rp), and PKIConf"),
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    { "no_cache_extracerts", OPT_BOOL, {.bit = false},
      { (const char **) &opt_no_cache_extracerts },
      "Do not keep certificates received in the extraCerts CMP message field"},
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30200000L || defined USE_LIBCMP
    { "srvcertout", OPT_TXT, {.txt = NULL}, { &opt_srvcertout },
      "File to save server cert used and validated for CMP response protection"},
#endif
    { "extracertsout", OPT_TXT, {.txt = NULL}, { &opt_extracertsout },
      "File to save extra certificates received in the extraCerts field"},
    { "extracerts_dir", OPT_TXT, {.txt = NULL}, { &opt_extracerts_dir },
      "Path to save not self-issued extra certs received in the extraCerts field"},
    { "extracerts_dir_format", OPT_TXT, {.txt = "pem"},
      { &opt_extracerts_dir_format },
      "Format to use for saving those certs. Default \"pem\""},
    { "cacertsout", OPT_TXT, {.txt = NULL}, { &opt_cacertsout },
      "File to save certificates received in caPubs field or genp of type caCerts"},
    { "cacerts_dir", OPT_TXT, {.txt = NULL}, { &opt_cacerts_dir },
      "Path to save self-issued CA certs received in the caPubs field"},
    { "cacerts_dir_format", OPT_TXT, {.txt = "pem"},
      { &opt_cacerts_dir_format },
      "Format to use for saving those certs. Default \"pem\""},
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    { "oldwithold", OPT_TXT, {.txt = NULL}, { &opt_oldwithold },
      "Root CA certificate to request update for in genm of type rootCaCert"},
    { "newwithnew", OPT_TXT, {.txt = NULL}, { &opt_newwithnew },
      "File to save NewWithNew cert received in genp of type rootCaKeyUpdate"},
    { "newwithold", OPT_TXT, {.txt = NULL}, { &opt_newwithold },
      "File to save NewWithOld cert received in genp of type rootCaKeyUpdate"},
    { "oldwithnew", OPT_TXT, {.txt = NULL}, { &opt_oldwithnew },
      "File to save OldWithNew cert received in genp of type rootCaKeyUpdate"},
    { "oldcrl", OPT_TXT, {.txt = NULL}, { &opt_oldcrl },
      "CRL to request update for in genm of type crlStatusList"},
    { "crlout", OPT_TXT, {.txt = NULL}, { &opt_crlout },
      "File to save new CRL received in genp of type 'crls'"},
#endif

    OPT_HEADER("Client authentication and protection"),
    { "ref", OPT_TXT, {.txt = NULL}, { &opt_ref },
      "Reference value to use as senderKID in case no -cert is given"},
    { "secret", OPT_TXT, {.txt = NULL}, { &opt_secret },
      "Source of secret value for authentication with a pre-shared key (PBM)"},
    { "cert", OPT_TXT, {.txt = NULL}, { &opt_cert },
      "Client cert (plus any extra one), needed unless using -secret for PBM."},
    OPT_MORE("This also used as default reference for subject DN and SANs."),
    OPT_MORE("Any further certs included are appended to the untrusted certs"),
    { "own_trusted", OPT_TXT, {.txt = NULL}, { &opt_own_trusted },
      "Optional certs to validate chain building for own CMP signer cert"},
    { "key", OPT_TXT, {.txt = NULL}, { &opt_key },
      "Key for the client certificate to use for protecting requests"},
    { "keypass", OPT_TXT, {.txt = NULL}, { &opt_keypass },
      "Pass phrase source for the client -key, -cert, and -oldcert"},
    { "digest", OPT_TXT, {.txt = NULL}, { &opt_digest },
      "Digest alg to use in msg protection and POPO signatures. Default \"sha256\""},
    OPT_MORE("See the man page or online doc for hints on available algorithms"),
    { "mac", OPT_TXT, {.txt = NULL}, { &opt_mac},
      "MAC algorithm to use in PBM-based message protection. Default \"hmac-sha1\""},
    OPT_MORE("See the man page or online doc for hints on available algorithms"),
    { "extracerts", OPT_TXT, {.txt = NULL}, { &opt_extracerts },
      "File(s) with certificates to append in extraCerts field of outgoing messages."},
    OPT_MORE("This can be used as the default CMP signer cert chain to include"),
    { "unprotected_requests", OPT_BOOL, {.bit = false},
      { (const char **) &opt_unprotected_requests },
      "Send request messages without CMP-level protection"},

    OPT_HEADER("TLS connection"),
    { "tls_used", OPT_BOOL, {.bit = false}, { (const char **) &opt_tls_used },
      "Enable using TLS (also when other TLS options are not set)"},
    { "tls_cert", OPT_TXT, {.txt = NULL}, { &opt_tls_cert },
      "Client certificate (plus any extra certs) for TLS connection"},
    { "tls_key", OPT_TXT, {.txt = NULL}, { &opt_tls_key },
      "Client private key for TLS connection"},
    { "tls_keypass", OPT_TXT, {.txt = NULL}, { &opt_tls_keypass },
      "Client key and cert pass phrase source for TLS connection"},
    { "tls_extra", OPT_TXT, {.txt = NULL}, { &opt_tls_extra },
      "Extra certificates to provide to TLS server during TLS handshake"},
    { "tls_trusted", OPT_TXT, {.txt = NULL}, { &opt_tls_trusted },
      "File(s) with certs to trust for TLS server verification (TLS trust anchor)"},
    { "tls_host", OPT_TXT, {.txt = NULL}, { &opt_tls_host },
      "Address (rather than -server) to be checked during TLS hostname validation"},

    OPT_HEADER("Debugging"),
    {"reqin", OPT_TXT, {.txt = NULL}, { (const char **) &opt_reqin},
     "Take sequence of CMP requests to send to server from file(s)"},
    {"reqin_new_tid", OPT_BOOL, {.bit = false},
     { (const char **) &opt_reqin_new_tid},
     "Use fresh transactionID for CMP requests read from -reqin"},
    {"reqout", OPT_TXT, {.txt = NULL}, { (const char **) &opt_reqout},
     "Save sequence of CMP requests to file(s)"},
    {"rspin", OPT_TXT, {.txt = NULL}, { (const char **) &opt_rspin},
     "Process sequence of CMP responses provided in file(s), skipping server"},
    {"rspout", OPT_TXT, {.txt = NULL}, { (const char **) &opt_rspout},
     "Save sequence of CMP responses to file(s)"},

    OPT_HEADER("CMP and TLS certificate status checking"),
    /* TODO extend verification options and align with OpenSSL:apps/cmp.c */
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
    { "cdp_proxy", OPT_TXT, {.txt = NULL}, { &opt_cdp_proxy },
      "URL of the proxy server to send CDP URLs or cert isser names to"},
    { "crl_cache_dir", OPT_TXT, {.txt = NULL}, { &opt_crl_cache_dir },
      "Directory where to cache CRLs downloaded during verification."},
    { "crls_timeout", OPT_NUM, {.num = -1}, {(const char **)&opt_crls_timeout },
      "Timeout for CRL fetching, or 0 for none, -1 for default: 10 seconds"},
    { "crl_maxdownload_size", OPT_NUM, {.num = 0},
      { (const char **)&opt_crl_maxdownload_size},
      "Maximum size of a CRL to be downloaded. Default: 0 = OpenSSL default = 100 kiB"},
    { "use_aia", OPT_BOOL, {.bit = false}, { (const char **) &opt_use_aia },
      "Enable OCSP-based status checking and enable using any AIA entries in certs"},
    { "ocsp", OPT_TXT, {.txt = NULL}, {&opt_ocsp},
      "Enable OCSP-based status checking and use given OCSP responder(s) as fallback"},
    { "ocsp_timeout", OPT_NUM, {.num = -1}, {(const char **)&opt_ocsp_timeout },
      "Timeout for getting OCSP responses, or 0 for none, -1 for default: 10 seconds"},
    { "ocsp_last", OPT_BOOL, {.bit = false}, { (const char **) &opt_ocsp_last },
      "Do OCSP-based status checks last (else before using CRLs downloaded from CDPs)"},
    { "stapling", OPT_BOOL, {.bit = false}, { (const char **) &opt_stapling },
      "Enable OCSP stapling for TLS; is tried before any other cert status checks"},

    OPT_V_OPTIONS, /* excludes "crl_check" and "crl_check_all" */

    OPT_END
};

#ifndef SECUTILS_NO_TLS
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
#endif

static int set_gennames(OSSL_CMP_CTX *ctx, char *names, const char *desc)
{
    char *next;
    GENERAL_NAME *n;

    for (; names != NULL; names = next) {
        next = UTIL_next_item(names);

        if (strcmp(names, "critical") == 0) {
            (void)OSSL_CMP_CTX_set_option(ctx,
                                          OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL,
                                          1);
            continue;
        }

        /* try IP address first, then email/URI/domain name */
        (void)ERR_set_mark();
        n = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_IPADD, names, 0);
        if (n == NULL)
            n = a2i_GENERAL_NAME(NULL, NULL, NULL,
                                 strchr(names, '@') != NULL ? GEN_EMAIL :
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

static SSL_CTX *setup_TLS(STACK_OF(X509) *untrusted_certs)
{
#ifdef SECUTILS_NO_TLS
    (void)untrusted_certs;
    LOG_err("TLS is not enabled in this build");
    return NULL;
#else
    CREDENTIALS *tls_creds = NULL;
    SSL_CTX *tls = NULL;

    X509_STORE *tls_trust = NULL;
    static const char *tls_ciphers = NULL;
    /* or, e.g., "HIGH:!ADH:!LOW:!EXP:!MD5:@STRENGTH"; */
    const int security_level = -1;

    if (opt_tls_trusted != NULL) {
        tls_trust = STORE_load(opt_tls_trusted, "trusted certs for TLS level",
                               NULL /* no vpm: prevent strict checking */);
        if (tls_trust == NULL)
            goto err;
        if (!STORE_set_parameters(tls_trust, vpm,
                                  opt_check_all, opt_stapling, crls,
                                  opt_use_cdp, opt_cdps, (int)opt_crls_timeout,
                                  opt_use_aia, opt_ocsp, (int)opt_ocsp_timeout))
            goto err;
        if (!STORE_set_crl_callback(tls_trust, CRLMGMT_load_crl_cb, cmdata))
            goto err;
    } else {
        LOG_warn("-tls_used given without -tls_trusted; will not authenticate the TLS server");
    }

    if (opt_tls_cert != NULL || opt_tls_key != NULL
            || opt_tls_keypass != NULL) {
        if (opt_tls_key == NULL) {
            LOG_err("missing -tls_key option");
            goto err;
        } else if (opt_tls_cert == NULL) {
            LOG_err("missing -tls_cert option");
            goto err;
        }
    }
    if (opt_tls_key != NULL) {
        tls_creds = CREDENTIALS_load(opt_tls_cert, opt_tls_key, opt_tls_keypass,
                                     "credentials for TLS level");
        if (tls_creds == NULL)
            goto err;
    } else {
        LOG_warn("-tls_used given without -tls_key; cannot authenticate to the TLS server");
    }
    tls = TLS_new(tls_trust, untrusted_certs, tls_creds, tls_ciphers,
                  security_level);
    if (tls == NULL)
        goto err;

    /*
     * Enable and parameterize server hostname/IP address check.
     * If we did this before checking our own TLS cert in TLS_new(),
     * the expected hostname would mislead the check.
     */
    if (tls_trust != NULL) {
        const char *host = opt_tls_host != NULL ? opt_tls_host : opt_server;

        if (!STORE_set1_host_ip(tls_trust, host, host))
            goto err;
    }

    /* If present we append to the list also the certs from opt_tls_extra */
    if (opt_tls_extra != NULL) {
        STACK_OF(X509) *tls_extra = CERTS_load(opt_tls_extra,
                                               "extra certificates for TLS",
                                               1 /* CA */, vpm);

        if (tls_extra == NULL
                || !SSL_CTX_add_extra_chain_free(tls, tls_extra)) {
            SSL_CTX_free(tls);
            tls = NULL;
            goto err;
        }
    }

 err:
    STORE_free(tls_trust);
    CREDENTIALS_free(tls_creds);
    return tls;
#endif
}

static X509_STORE *setup_CMP_truststore(const char *trusted_cert_files)
{
    if (trusted_cert_files == NULL)
        return NULL;
    X509_STORE *cmp_truststore =
        STORE_load(trusted_cert_files, "trusted certs for CMP level",
                   NULL /* no vpm: prevent strict checking */);

    if (cmp_truststore == NULL)
        goto err;
    if (!STORE_set_parameters(cmp_truststore, vpm,
                              opt_check_all, false /* stapling */, crls,
                              opt_use_cdp, opt_cdps, (int)opt_crls_timeout,
                              opt_use_aia, opt_ocsp, (int)opt_ocsp_timeout) ||
        !STORE_set_crl_callback(cmp_truststore, CRLMGMT_load_crl_cb, cmdata) ||
        /* clear any expected host/ip/email address; use opt_expect_sender: */
        !STORE_set1_host_ip(cmp_truststore, NULL, NULL)) {
        STORE_free(cmp_truststore);
        cmp_truststore = NULL;
    }

 err:
    return cmp_truststore;
}

static X509_EXTENSIONS *setup_X509_extensions(CMP_CTX *ctx)
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

        if ((policy = OBJ_txt2obj(opt_policy_oids, 0)) == NULL) {
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

/*
 * write OSSL_CMP_MSG DER-encoded in turn to the next element in
 * the string of file names, which is consumed step by step
 */
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
static OSSL_CMP_MSG *read_PKIMESSAGE(OSSL_CMP_CTX *ctx,
                                     const char *desc, char **filenames)
{
    char *file;
    OSSL_CMP_MSG *ret;

    if (filenames == NULL || desc == NULL) {
        LOG_err("NULL arg to read_PKIMESSAGE");
        return NULL;
    }
    if (*filenames == NULL) {
        LOG_err("Not enough file names provided for reading PKIMessage");
        return NULL;
    }

    file = *filenames;
    *filenames = UTIL_next_item(file);

    ret = OSSL_CMP_MSG_read(file, OSSL_CMP_CTX_get0_libctx(ctx),
                            OSSL_CMP_CTX_get0_propq(ctx));
    if (ret == NULL)
        LOG(FL_ERR, "Cannot read PKIMessage from file '%s'", file);
    else
        LOG(FL_INFO, "%s %s", desc, file);
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
    const char *prev_opt_rspin = opt_rspin;

    if (opt_reqout != NULL && !write_PKIMESSAGE(req, &opt_reqout))
        goto err;
    if (opt_reqin != NULL && opt_rspin == NULL) {
        if ((req_new = read_PKIMESSAGE(ctx,
                                       "actually sending", &opt_reqin)) == NULL)
            goto err;
        /*-
         * The transaction ID in req_new read from opt_reqin may not be fresh.
         * In this case the server may complain "Transaction id already in use."
         * The following workaround unfortunately requires re-protection.
         */
        if (opt_reqin_new_tid
                && !OSSL_CMP_MSG_update_transactionID(ctx, req_new))
            goto err;

        /*
         * Except for first request, need to satisfy recipNonce check by server.
         * Unfortunately requires re-protection if the request was protected.
         */
#if OPENSSL_VERSION_NUMBER >= 0x30000090L || defined USE_LIBCMP
        if (!OSSL_CMP_MSG_update_recipNonce(ctx, req_new))
            goto err;
#endif
    }

    if (opt_rspin != NULL) {
        res = read_PKIMESSAGE(ctx, "actually using", &opt_rspin);
    } else {
        const OSSL_CMP_MSG *actual_req = req_new != NULL ? req_new : req;

        res =
#if 0 /* TODO add in case mock server functionality is included */
            opt_use_mock_srv ? OSSL_CMP_CTX_server_perform(ctx, actual_req) :
#endif
            OSSL_CMP_MSG_http_perform(ctx, actual_req);
    }
    if (res == NULL)
        goto err;

    if (req_new != NULL || prev_opt_rspin != NULL) {
        /* need to satisfy nonce and transactionID checks by client */
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

static int set_name(OPTIONAL const char *str,
                    int (*set_fn) (OSSL_CMP_CTX *ctx, const X509_NAME *name),
                    OSSL_CMP_CTX *ctx, const char *desc)
{
    if (str != NULL) {
        X509_NAME *n = UTIL_parse_name(str, MBSTRING_ASC, false);

        if (n == NULL) {
            LOG(FL_ERR, "cannot parse %s DN '%s'", desc, str);
            return -03;
        }
        if (!(*set_fn) (ctx, n)) {
            X509_NAME_free(n);
            LOG_err("Out of memory");
            return -04;
        }
        X509_NAME_free(n);
    }
    return CMP_OK;
}

static int setup_cert_template(CMP_CTX *ctx)
{
    int err;

    err = set_name(opt_issuer, OSSL_CMP_CTX_set1_issuer, ctx, "issuer");
    if (err != CMP_OK)
        goto err;

    if (opt_san_nodefault) {
        if (opt_sans != NULL)
            LOG_warn("-san_nodefault has no effect when -sans is used");
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT,
                                     1)) {
            LOG_err("Failed to set 'SubjectAltName_nodefault' field of CMP context");
            goto err;
        }
    }

    if (!set_gennames(ctx, opt_sans, "Subject Alternative Name")) {
        LOG_err("Failed to set 'Subject Alternative Name' of CMP context");
        err = -39;
        goto err;
    }

 err:
    return err;
}

static int handle_opt_geninfo(OSSL_CMP_CTX *ctx)
{
    ASN1_OBJECT *obj = NULL;
    ASN1_TYPE *type = NULL;
    long value;
    ASN1_INTEGER *aint = NULL;
    ASN1_UTF8STRING *text = NULL;
    OSSL_CMP_ITAV *itav;
    char *ptr = opt_geninfo, *oid, *end;
    int ret = -28;

    do {
        while (isspace(*ptr))
            ptr++;
        oid = ptr;
        if ((ptr = strchr(oid, ':')) == NULL) {
            LOG(FL_ERR, "Missing ':' in -geninfo arg %.40s", oid);
            return CMP_R_INVALID_ARGS;
        }
        *ptr++ = '\0';
        if ((obj = OBJ_txt2obj(oid, 0)) == NULL) {
            LOG(FL_ERR, "Cannot parse OID in -geninfo arg %.40s", oid);
            return CMP_R_INVALID_ARGS;
        }
        if ((type = ASN1_TYPE_new()) == NULL) {
            LOG_err("Out of memory");
            goto err;
        }

        if (strncmp(ptr, "int:", 4) == 0) {
            value = strtol(ptr += 4, &end, 10);
            if (end == ptr) {
                LOG(FL_ERR, "Cannot parse int in -geninfo arg %.40s", ptr);
                ret = CMP_R_INVALID_ARGS;
                goto err;
            }
            ptr = end;
            if (*ptr != '\0') {
                if (*ptr != ',') {
                    LOG(FL_ERR, "Missing ',' or end of -geninfo arg after int at %.40s",
                        ptr);
                    ret = CMP_R_INVALID_ARGS;
                    goto err;
                }
                ptr++;
            }

            if ((aint = ASN1_INTEGER_new()) == NULL
                    || !ASN1_INTEGER_set(aint, value)) {
                LOG_err("Out of memory");
                goto err;
            }
            ASN1_TYPE_set(type, V_ASN1_INTEGER, aint);
            aint = NULL;

        } else if (strncmp(ptr, "str:", 4) == 0) {
            end = strchr(ptr += 4, ',');
            if (end == NULL)
                end = ptr + strlen(ptr);
            else
                *end++ = '\0';
            if ((text = ASN1_UTF8STRING_new()) == NULL
                    || !ASN1_STRING_set(text, ptr, -1)) {
                LOG_err("Out of memory");
                goto err;
            }
            ptr = end;
            ASN1_TYPE_set(type, V_ASN1_UTF8STRING, text);
            text = NULL;

        } else {
            LOG(FL_ERR, "Missing 'int:' or 'str:' in -geninfo arg %.40s", ptr);
            ret = CMP_R_INVALID_ARGS;
            goto err;
        }

        if ((itav = OSSL_CMP_ITAV_create(obj, type)) == NULL) {
            LOG_err("Unable to create 'OSSL_CMP_ITAV' structure");
            goto err;
        }
        obj = NULL;
        type = NULL;

        if (!OSSL_CMP_CTX_push0_geninfo_ITAV(ctx, itav)) {
            LOG_err("Failed to add ITAV for geninfo of the PKI message header");
            OSSL_CMP_ITAV_free(itav);
            return -10;
        }
    } while (*ptr != '\0');
    return CMP_OK;

 err:
    ASN1_OBJECT_free(obj);
    ASN1_TYPE_free(type);
    ASN1_INTEGER_free(aint);
    ASN1_UTF8STRING_free(text);
    return ret;
}

static int setup_ctx(CMP_CTX *ctx)
{
    CMP_err err = set_name(opt_expect_sender, OSSL_CMP_CTX_set1_expected_sender,
                           ctx, "expected sender");

    if (err != CMP_OK)
        return err;

    err = CMP_R_INVALID_ARGS;
    if (!OSSL_CMP_CTX_set_log_verbosity(ctx, (int)opt_verbosity))
        return err;
    if (opt_extracerts != NULL) {
        STACK_OF(X509) *certs =
            CERTS_load(opt_extracerts, "extra certificates for CMP",
                       -1 /* allow EE and CA */, vpm);

        if (certs == NULL) {
            LOG(FL_ERR, "Unable to load '%s' extra certificates for CMP",
                opt_extracerts);
            err = CMP_R_LOAD_CERTS;
            goto err;
        } else {
            if (!OSSL_CMP_CTX_set1_extraCertsOut(ctx, certs)) {
                LOG_err("Failed to set 'extraCerts' field of CMP context");
                CERTS_free(certs);
                err = -05;
                goto err;
            }
            CERTS_free(certs);
        }
    }

    if (opt_popo < OSSL_CRMF_POPO_NONE - 1
            || opt_popo > OSSL_CRMF_POPO_KEYENC) {
        LOG(FL_ERR, "Invalid value '%d' for popo method (must be between -1 and 2)",
            opt_popo);
        err = -11;
        goto err;
    }

    if ((int)opt_days < 0) {
        LOG(FL_ERR, "Only non-negative values allowed for -days",
            opt_days);
        err = -12;
        goto err;
    }
    /* set option flags directly via CMP API */
    if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_ERRORS,
                                 opt_unprotected_errors ? 1 : 0)
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_NO_CACHE_EXTRACERTS,
                                    opt_no_cache_extracerts ? 1 : 0)
#endif
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IGNORE_KEYUSAGE,
                                    opt_ignore_keyusage ? 1 : 0)
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_VALIDITY_DAYS,
                                    (int)opt_days)
        || (opt_popo >= OSSL_CRMF_POPO_NONE
            && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_POPO_METHOD,
                                        (int)opt_popo))
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DISABLE_CONFIRM,
                                    opt_disable_confirm ? 1 : 0)
        || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_SEND,
                                    opt_unprotected_requests ? 1 : 0)) {
        LOG_err("Failed to set option flags of CMP context");
        goto err;
    }

    if (opt_profile != NULL) {
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
        err = CMPclient_add_certProfile(ctx, opt_profile);
#else
        LOG_err("-profile option is not supported for OpenSSL < 3.2");
        err = -29;
#endif
        if (err != CMP_OK)
            goto err;
    }
    if (opt_geninfo != NULL && (err = handle_opt_geninfo(ctx)) != CMP_OK)
        goto err;
    err = CMP_OK;

 err:
    return err;
}

static CMP_err prepare_CMP_client(CMP_CTX **pctx, enum use_case use_case,
                                  OPTIONAL LOG_cb_t log_fn)
{
    X509_STORE *new_cert_truststore = NULL;
    X509_STORE *own_truststore = NULL;
    X509_STORE *cmp_truststore = NULL;
    STACK_OF(X509) *untrusted_certs = NULL;
    CREDENTIALS *cmp_creds = NULL;
    OSSL_CMP_transfer_cb_t transfer_fn = NULL; /* default HTTP(S) transfer */
    const bool implicit_confirm = opt_implicit_confirm;
    CMP_err err = -02;

    use_case = use_case + 0; /* prevent warning on unused parameter */
    const char *new_cert_trusted =
        opt_out_trusted == NULL ? opt_srvcert : opt_out_trusted;
    if (new_cert_trusted != NULL) {
        LOG(FL_TRACE, "Using '%s' as trust store for validating new cert",
            new_cert_trusted);
        new_cert_truststore =
            STORE_load(new_cert_trusted,
                       "trusted certs for validating new cert", vpm);
        if (new_cert_truststore == NULL)
            goto err;
        /* use separate flag for checking any cert, for new certificate store */
        /* any -verify_hostname, -verify_ip, and -verify_email apply here */
        /* no cert status/revocation checks done for newly enrolled cert */
        if (!STORE_set_parameters(new_cert_truststore, vpm,
                                  false, false, NULL,
                                  false, NULL, -1,
                                  false, NULL, -1))
            goto err;
        if (!STORE_set_crl_callback(new_cert_truststore, CRLMGMT_load_crl_cb,
                                    cmdata))
            goto err;
    }
    /* cannot set these vpm options before above STORE_set_parameters(...) */
    if (opt_check_any)
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_STATUS_CHECK_ANY);
    if (opt_ocsp_last)
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_OCSP_LAST);

    if (opt_secret != NULL || opt_key != NULL) {
        const char *const creds_desc = "credentials for CMP level";

        if ((cmp_creds = CREDENTIALS_load(opt_cert, opt_key, opt_keypass,
                                          creds_desc)) == NULL) {
            LOG(FL_ERR, "Unable to set up %s", creds_desc);
            err = CMP_R_LOAD_CREDS;
            goto err;
        }
        if (opt_secret != NULL) {
            /* use PBM except for kur and rr if secret is present */
            char *secret = FILES_get_pass(opt_secret,
                                          "PBM-based message protection");

            if (secret == NULL) {
                LOG(FL_ERR, "Unable to set up secret part of %s", creds_desc);
                err = CMP_R_LOAD_CREDS;
                goto err;
            }
            (void)CREDENTIALS_set_pwd(cmp_creds, secret);
        }
        if (opt_ref != NULL)
            (void)CREDENTIALS_set_pwdref(cmp_creds, OPENSSL_strdup(opt_ref));
        if (opt_own_trusted != NULL) {
            if (opt_cert == NULL) {
                LOG_warn("-own_trusted option is ignored since -cert not given");
            } else {
                LOG(FL_TRACE, "Using '%s' as trust store for validating own CMP signer cert",
                    opt_own_trusted);
                own_truststore =
                    STORE_load(opt_own_trusted,
                               "trusted certs for validating own CMP signer cert",
                               vpm);
                err = -06;
                if (own_truststore == NULL)
                    goto err;
                err = -07;
                /* no cert status/revocation checks done for here */
                if (!STORE_set_parameters(own_truststore, NULL /* vpm */,
                                          false, false, NULL,
                                          false, NULL, -1,
                                          false, NULL, -1))
                    goto err;
            }
        }
    } else {
        if (opt_own_trusted != NULL)
            LOG_warn("-own_trusted option is ignored since -cert and -key are not used");
    }

    err = CMP_R_LOAD_CERTS;
    if (opt_srvcert != NULL && opt_trusted != NULL) {
        LOG_warn("-trusted option is ignored since -srvcert option is present");
        opt_trusted = NULL;
    }
    cmp_truststore = setup_CMP_truststore(opt_trusted);
    untrusted_certs = opt_untrusted == NULL ? NULL :
        CERTS_load(opt_untrusted, "untrusted certs", 1 /* CA */, vpm);
    if ((cmp_truststore == NULL && opt_trusted != NULL)
            || (untrusted_certs == NULL && opt_untrusted != NULL))
        goto err;

    if (opt_reqin != NULL && opt_rspin != NULL)
        LOG_warn("-reqin is ignored since -rspin is present");
    if (opt_reqin_new_tid && opt_reqin == NULL)
        LOG_warn("-reqin_new_tid is ignored since -reqin is not present");
    if (opt_reqin != NULL || opt_reqout != NULL
            || opt_rspin != NULL || opt_rspout != NULL)
        transfer_fn = read_write_req_resp;

    if ((int)opt_crl_maxdownload_size < 0) {
        LOG_err("Only non-negative values allowed for -crl_maxdownload_size");
        err = -50;
        goto err;
    }
    if ((int)opt_total_timeout < -1) {
        LOG_err("Only non-negative values allowed for -total_timeout");
        err = -69;
        goto err;
    }
    err = CMPclient_prepare(pctx, NULL /* libctx */, NULL /* propq */, log_fn,
                            cmp_truststore, opt_recipient,
                            untrusted_certs,
                            cmp_creds, own_truststore,
                            opt_digest, opt_mac,
                            transfer_fn, (int)opt_total_timeout,
                            new_cert_truststore, implicit_confirm);
    if (err != CMP_OK)
        goto err;

    if (opt_srvcert != NULL) {
        X509 *srvcert = CERT_load(opt_srvcert, NULL /* pass */,
                                  "directly trusted CMP server certificate",
                                  -1 /* no type check */, vpm);

        if (srvcert == NULL || !OSSL_CMP_CTX_set1_srvCert(*pctx, srvcert))
            err = -8;
        X509_free(srvcert);
    }

    /* on CMP_OK, still need to free resources, so falling through */
 err:
    CREDENTIALS_free(cmp_creds);
    CERTS_free(untrusted_certs);
    STORE_free(new_cert_truststore);
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

static int setup_transfer(CMP_CTX *ctx)
{
    CMP_err err;

    if (opt_keep_alive < 0 || opt_keep_alive > 2) {
        LOG_err("-keep_alive argument must be 0, 1, or 2");
        err = -13;
        goto err;
    }

    if ((int)opt_msg_timeout < 0) {
        LOG_err("Only non-negative values allowed for -msg_timeout");
        err = -14;
        goto err;
    }

    if (opt_server == NULL) {
        if (opt_rspin == NULL) {
            LOG_err("missing -server or -rspin option");
            err = -15;
            goto err;
        }
        if (opt_proxy != NULL)
            LOG_warn("ignoring -proxy option since -server is not given");
        if (opt_no_proxy != NULL)
            LOG_warn("ignoring -no_proxy option since -server is not given");
        if (opt_tls_used) {
            LOG_warn("ignoring -tls_used option since -server is not given");
            opt_tls_used = 0;
        }
    } else {
        if (opt_rspin != NULL) {
            LOG_warn("ignoring -server option since -rspin is given");
            opt_server = NULL;
        }
    }
    if (opt_tls_cert == NULL && opt_tls_key == NULL && opt_tls_keypass == NULL
            && opt_tls_extra == NULL && opt_tls_trusted == NULL
            && opt_tls_host == NULL) {
        if (opt_tls_used)
            LOG_warn("-tls_used given without any other TLS options");
    } else if (!opt_tls_used) {
        LOG_warn("TLS options(s) are ignored since -tls_used is not given");
    }

    SSL_CTX *tls = NULL;
    if (opt_tls_used
            && (tls = setup_TLS(OSSL_CMP_CTX_get0_untrusted(ctx))) == NULL) {
        LOG_err("Unable to set up TLS for CMP client");
        err = -16;
        goto err;
    }

    err = CMPclient_setup_HTTP(ctx, opt_server, opt_path,
                               (int)opt_keep_alive, (int)opt_msg_timeout,
                               tls, opt_proxy, opt_no_proxy);

#ifndef SECUTILS_NO_TLS
    TLS_free(tls);
#endif
    if (err != CMP_OK) {
        LOG_err("Unable to set up HTTP for CMP client");
        goto err;
    }
 err:
    return err;
}

/* file (path) name using prefix, subject DN, "_", hash, ".", and suffix */
static size_t get_cert_filename(const X509 *cert, const char *prefix,
                                const char *suffix,
                                char *buf, size_t buf_len)
{
    if (buf == NULL || buf_len == 0)
        return 0;

    size_t ret, len = UTIL_safe_string_copy(prefix, buf, buf_len, NULL);
    if (len == 0)
        return 0;

    char subject[256], *p;
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName,
                                  subject, sizeof(subject)) <= 0)
        return 0;
    ret = UTIL_safe_string_copy(subject, buf + len, buf_len - len, NULL);
    if (ret == 0)
        return 0;
    for (p = buf + len; *p != '\0'; p++)
        if (*p == ' ')
            *p = '_';
    len += ret;
    if ((ret = UTIL_safe_string_copy("_", buf + len, buf_len - len, NULL)) == 0)
        return 0;
    len += ret;

    unsigned char sha1[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    X509_digest(cert, EVP_sha1(), sha1, &size);
    ret = UTIL_bintohex(sha1, size, false, '-', 4,
                        buf + len, buf_len - len, NULL);
    if (ret == 0)
        return 0;
    len += ret;
    if ((ret = UTIL_safe_string_copy(".", buf + len, buf_len - len, NULL)) == 0)
        return 0;
    len += ret;

    ret = UTIL_safe_string_copy(suffix, buf + len, buf_len - len, NULL);
    if (ret == 0)
        return 0;
    for (p = buf + len; *p != '\0'; p++)
        *p = (char)tolower(*p);
    len += ret;
    return len;
}

static bool validate_cert(void)
{
    X509 *target;
    X509_STORE *store;
    STACK_OF(X509) *untrusted = NULL;
    bool ret = false;

    if (opt_tls_cert != NULL) {
        if (opt_tls_trusted == NULL) {
            LOG_err("Missing -tls_trusted option for target certificate given by -tls_cert");
            return false;
        }
        opt_keypass = opt_tls_keypass;
        opt_cert = opt_tls_cert;
        opt_trusted = opt_tls_trusted;
    } else if (opt_cert != NULL) {
        if (opt_own_trusted == NULL) {
            LOG_err("Missing -own_trusted option for target certificate given by -cert");
            return false;
        }
        opt_trusted = opt_own_trusted;
    } else {
        LOG_err("Missing -cert option for target certificate");
        return false;
    }

    LOG(FL_INFO, "Validating certificate, optionally including revocation status ");
#define STR_OR_NONE(s) (s != NULL ? s : "(none)")
    LOG(FL_INFO, "Target certificate: %s", STR_OR_NONE(opt_cert));
    LOG(FL_INFO, "Trusted certs: %s", STR_OR_NONE(opt_trusted));
    LOG(FL_INFO, "Untrusted certs: %s", STR_OR_NONE(opt_untrusted));

    target = CERT_load(opt_cert, opt_keypass, "target cert",
                       -1 /* no type check */, vpm);
    if (target == NULL)
        return false;
    LOG(FL_DEBUG, "Target certificate read successfully:");
    LOG_cert_CDP(FL_DEBUG, target);

    /* TODO combine with part of prepare_CMP_client() */
    store = STORE_load(opt_trusted,
                       "trusted certs for validating certificate", vpm);
    if (store == NULL)
        goto err;
    if (opt_untrusted != NULL &&
        (untrusted = CERTS_load(opt_untrusted, "untrusted certs",
                                -1 /* allow also non-CA certs */, vpm)) == NULL)
        goto err;

    if (!STORE_set_parameters(store, vpm,
                              opt_check_all, opt_stapling, crls,
                              opt_use_cdp, opt_cdps, (int)opt_crls_timeout,
                              opt_use_aia, opt_ocsp, (int)opt_ocsp_timeout))
        goto err;

    if (!STORE_set_crl_callback(store, CRLMGMT_load_crl_cb, cmdata))
        goto err;

    ret = CREDENTIALS_verify_cert(NULL /* uta_ctx */, target, untrusted, store)
        > 0;
    if (ret)
        LOG(FL_INFO, "Certificate verification finished successfully");
    else
        LOG(FL_ERR, "Certificate verification failed");

err:
    X509_STORE_free(store);
    CERTS_free(untrusted);
    X509_free(target);
    return ret;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# if OPENSSL_VERSION_NUMBER < 0x30200000L
static int add_object(unsigned char *data, int len, int nid, const char *name)
{
    ASN1_OBJECT *obj;
    int res;

    ERR_set_mark();
    res = OBJ_nid2obj(nid) != NULL;
    ERR_pop_to_mark();
    if (res)
        return 1;

    if ((obj = ASN1_OBJECT_create(nid, data, len, name, name)) == NULL)
        return 0;
    res = OBJ_add_object(obj) != NID_undef;
    ASN1_OBJECT_free(obj);
    if (!res)
        LOG(FL_ERR, "Error adding info for ASN.1 object %s", name);
    return res;
}
# endif
#endif

/* Add any missing OIDs needed for genm */
static int complete_genm_asn1_objects(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# if OPENSSL_VERSION_NUMBER < 0x30200000L
    static unsigned char so_rootCaCert[] =
        { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x14 };
    static unsigned char so_certProfile[] =
        { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x15 };
    static unsigned char so_crlStatusList[] =
        { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x16 };
    static unsigned char so_crls[] =
        { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x17 };
    static unsigned char so_algId[] =
        { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x0B };
    static unsigned char so_rsaKeyLen[] =
        { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x05, 0x01, 0x0C };
#  if OPENSSL_VERSION_NUMBER < 0x30000000L
    static unsigned char so_rootCaKeyUpdate[] =
        { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x12 };
    static unsigned char so_certReqTemplate[] =
        { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x13 };

    if (!add_object(so_rootCaKeyUpdate, sizeof(so_rootCaKeyUpdate),
                    NID_id_it_rootCaKeyUpdate, "id-it-rootCaKeyUpdate")
        || !add_object(so_certReqTemplate, sizeof(so_certReqTemplate),
                       NID_id_it_certReqTemplate, "id-it-certReqTemplate"))
        return -20;
#  endif
    if (!add_object(so_rootCaCert, sizeof(so_rootCaCert),
                    NID_id_it_rootCaCert, "id-it-rootCaCert")
        || !add_object(so_certProfile, sizeof(so_certProfile),
                       NID_id_it_certProfile, "id-it-certProfile")
        || !add_object(so_crlStatusList, sizeof(so_crlStatusList),
                       NID_id_it_crlStatusList, "id-it-crlStatusList")
        || !add_object(so_crls, sizeof(so_crls),
                       NID_id_it_crls, "id-it-crls")
        || !add_object(so_algId, sizeof(so_algId),
                       NID_id_regCtrl_algId, "id-regCtrl-algId")
        || !add_object(so_rsaKeyLen, sizeof(so_rsaKeyLen),
                       NID_id_regCtrl_rsaKeyLen, "id-regCtrl-rsaKeyLen"))
        return -21;
# endif
#endif
    return CMP_OK;
}

static CMP_err check_options(enum use_case use_case)
{
    if (opt_centralkeygen) {
        if (opt_popo > OSSL_CRMF_POPO_NONE) {
            LOG(FL_ERR, "-popo value %ld is inconsistent with -centralkeygen",
                opt_popo);
            return -17;
        }
        opt_popo = OSSL_CRMF_POPO_NONE;
        /* TODO document the use of OSSL_CRMF_POPO_NONE for central key generation */
    }
    if (opt_popo == OSSL_CRMF_POPO_NONE)
        opt_centralkeygen = true;

    if (opt_infotype == NULL) {
#if 0
        if (use_case == genm) {
            LOG_err("no -infotype option given for genm");
            return -51;
        }
#else
        opt_infotype = "";
#endif
    } else if (use_case != genm) {
        LOG_warn("-infotype option is ignored for commands other than 'genm'");
    } else {
        char id_buf[100] = "id-it-";

        strncat(id_buf, opt_infotype, sizeof(id_buf) - strlen(id_buf) - 1);
        if ((infotype = OBJ_sn2nid(id_buf)) == NID_undef) {
            LOG(FL_ERR, "Unknown OID name '%s' in -infotype option", id_buf);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
            if (strcmp(opt_infotype, "caCerts") == 0
                || strcmp(opt_infotype, "certReqTemplate") == 0)
                LOG(FL_INFO, "infoType %s is not supported for OpenSSL < 3.0",
                    opt_infotype);
#endif
#if OPENSSL_VERSION_NUMBER < 0x30200000L && OPENSSL_VERSION_NUMBER < 0x30000000L
            if (strcmp(opt_infotype, "rootCaCert") == 0
                || strcmp(opt_infotype, "crlStatusList") == 0)
                LOG(FL_INFO, "infoType %s is not supported for OpenSSL < 3.0",
                    opt_infotype);
#endif
            return -30;
        }
    }
    if (use_case != genm || strcmp(opt_infotype, "rootCaCert")) {
        const char *msg = "option is ignored unless -cmd 'genm' and -infotype 'rootCaCert' is given";

        if (opt_oldwithold != NULL)
            LOG(FL_WARN, "-oldwithold %s", msg);
        if (opt_newwithnew != NULL)
            LOG(FL_WARN, "-newwithnew %s", msg);
        if (opt_newwithold != NULL)
            LOG(FL_WARN, "-newwithold %s", msg);
        if (opt_oldwithnew != NULL)
            LOG(FL_WARN, "-oldwithnew %s", msg);
    }
    if (use_case != genm || strcmp(opt_infotype, "certReqTemplate") != 0) {
        const char *msg = "option is ignored unless -cmd 'genm' and -infotype 'certReqTemplate' is given";

        if (opt_template != NULL)
            LOG(FL_WARN, "-template %s", msg);
    }
    if (use_case != genm || strcmp(opt_infotype, "crlStatusList") != 0) {
        const char *msg = "option is ignored unless -cmd 'genm' and -infotype 'crlStatusList' is given";

        if (opt_oldcrl != NULL)
            LOG(FL_WARN, "-oldcrl %s", msg);
    }

    if (!opt_secret && ((opt_cert == NULL) != (opt_key == NULL))) {
        LOG_err("Must give both -cert and -key options or neither");
        return -31;
    }
    if (use_case == update) {
        if (opt_oldcert == NULL && opt_csr == NULL) {
            LOG_err("Missing -oldcert for certificate to be updated and no -csr given");
            return -32;
        }
        if (opt_subject != NULL)
            LOG(FL_INFO, "Given -subject '%s' overrides the subject of '%s' for 'kur'",
                opt_subject, opt_oldcert != NULL ? opt_oldcert : opt_csr);
    } else {
        if (opt_secret != NULL && (opt_cert != NULL || opt_key != NULL))
            LOG_warn("-cert and -key not used since -secret option selects PBM-based message protection");
    }
    if (!opt_unprotected_requests && opt_secret == NULL && opt_key == NULL) {
        LOG_err("Must give client credentials unless -unprotected_requests is set");
        return -33;
    }

    if (opt_ref == NULL && opt_cert == NULL && opt_subject == NULL) {
        /* ossl_cmp_hdr_init() takes sender name from cert or else subject */
        /* TODO maybe else take as sender default the subjectName of oldCert or p10cr */
        LOG_err("Must give -ref if no -cert and no -subject given");
        return -34;
    }

    if (opt_check_all && opt_check_any) {
        LOG_warn("-check_all overrides -check_any");
    }

    if (use_case == pkcs10 && opt_csr == NULL) {
        LOG_err("-csr option is missing for command 'p10cr'");
        return -35;
    }
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    if (use_case == revocation) {
        if (opt_issuer == NULL && opt_serial == NULL) {
            if (opt_oldcert == NULL && opt_csr == NULL) {
                LOG_err("Missing -oldcert or -issuer and -serial for certificate to be revoked and no fallback -csr given");
                return -36;
            }
            if (opt_oldcert != NULL && opt_csr != NULL)
                LOG_warn("Ignoring -csr since -oldcert is given for command 'rr' (revocation)");
        } else {
#define OSSL_CMP_RR_MSG "since -issuer and -serial is given for command 'rr'"
            if (opt_issuer == NULL || opt_serial == NULL) {
                LOG_err("Must give both -issuer and -serial options or neither");
                return -73;
            }
            if (opt_oldcert != NULL)
                LOG_warn("Ignoring -oldcert " OSSL_CMP_RR_MSG);
            if (opt_csr != NULL)
                LOG_warn("Ignoring -csr " OSSL_CMP_RR_MSG);
        }
    } else {
        if (opt_serial != NULL)
            LOG_warn("Ignoring -serial for command other than 'rr'");
    }
#else
    if (use_case == revocation) {
        if (opt_oldcert == NULL && opt_csr == NULL) {
            LOG_err("Missing -oldcert for certificate to be revoked and no fallback -csr given");
            return -36;
        }
        if (opt_oldcert != NULL && opt_csr != NULL)
            LOG_warn("Ignoring -csr since -oldcert is given for command 'rr' (revocation)");
    }
#endif

    if (opt_cacerts_dir_format != NULL
            && FILES_get_format(opt_cacerts_dir_format) == FORMAT_UNDEF) {
        LOG_err("-cacerts_dir_format not accepted");
        return -9;
    }

    if (opt_extracerts_dir_format != NULL
            && FILES_get_format(opt_extracerts_dir_format) == FORMAT_UNDEF) {
        LOG_err("-extracerts_format not accepted");
        return -18;
    }

    bool crl_check = opt_crls != NULL || opt_use_cdp || opt_cdps != NULL;
    bool ocsp_check = opt_use_aia || opt_ocsp != NULL;
    if (opt_crls_timeout >= 0 && !opt_use_cdp && opt_cdps == NULL
        && (use_case != genm || strcmp(opt_infotype, "certReqTemplate") != 0)) {
        LOG_warn("Ignoring -crls_timeout since no -use_cdp, -cdps, or -infotype certReqTemplate option given");
    } else if (opt_crls_timeout < -1) {
        LOG(FL_ERR, "-crls_timeout value must be >= -1");
        return -22;
    }
    if (opt_ocsp_timeout >= 0 && !ocsp_check) {
        LOG_warn("Ignoring -ocsp_timeout since -use_aia and -ocsp options are not given");
    } else if (opt_ocsp_timeout < -1) {
        LOG(FL_ERR, "-ocsp_timeout value must be >= -1");
        return -23;
    }
    /* TODO check range of remaining numerical options */
    if ((crl_check || ocsp_check) && opt_trusted == NULL) {
        LOG_warn("Certificate status checks are enabled without providing the -trusted option");
    }
    if ((crl_check || ocsp_check || opt_stapling) && opt_tls_used
            && opt_tls_trusted == NULL) {
        LOG_warn("Cannot do TLS certificate status checks without -tls_trusted option");
    }
    if ((opt_check_all || opt_check_any) && !crl_check && !ocsp_check) {
        LOG_err("-check_all or -check_any is given without any option enabling use of CRLs or OCSP");
        return -37;
    }
    if (opt_ocsp_last && !ocsp_check) {
        LOG_err("-ocsp_last is given without -ocsp or -use_aia enabling OCSP-based cert status checking");
        return -38;
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
    return CMP_OK;
}

static CMP_err check_template_options(CMP_CTX *ctx, EVP_PKEY **new_pkey,
                                      X509 **oldcert, X509_REQ **csr,
                                      X509_EXTENSIONS **exts,
                                      enum use_case use_case)
{
    CMP_err err;

    if (use_case == pkcs10 || use_case == revocation || use_case == genm) {
        const char *msg = "option is ignored for 'p10cr', 'rr', and 'genm' commands";

        if (opt_newkeytype != NULL)
            LOG(FL_WARN, "-newkeytype %s", msg);
        if (opt_centralkeygen)
            LOG(FL_WARN, "-popo -1 or -centralkeygen %s", msg);
        if (opt_newkeypass != NULL)
            LOG(FL_WARN, "-newkeypass %s", msg);
        if (opt_newkey != NULL)
            LOG(FL_WARN, "-newkey %s", msg);
        if (opt_days != 0)
            LOG(FL_WARN, "-days %s", msg);
        if (opt_popo != OSSL_CRMF_POPO_NONE - 1)
            LOG(FL_WARN, "-popo %s", msg);
        if (use_case != pkcs10 && opt_out_trusted != NULL)
            LOG(FL_WARN, "-out_trusted is ignored for 'rr', and 'genm' commands");
    } else {
        if (opt_newkeytype != NULL || opt_centralkeygen) {
            if (opt_newkey == NULL) {
                LOG_err("Missing -newkey option specifying the file to save the new key");
                return -40;
            }
            if (opt_newkeytype != NULL && *opt_newkeytype != '\0') {
                /* TODO replace hack: gen preliminary key also when central key gen is requested to quickly get key algorithm identifier */
                const char *key_spec = strcmp(opt_newkeytype, "ECC") == 0
                    ? "EC:secp256r1" : opt_newkeytype;

                if ((*new_pkey = KEY_new(key_spec)) == NULL) {
                    LOG(FL_ERR, "Unable to generate new private key according to specification '%s'",
                        key_spec);
                    return CMP_R_GENERATE_KEY;
                }
            }
        } else if (opt_newkey != NULL) {
            const char *file = opt_newkey;
            const char *pass = opt_newkeypass;
            const char *desc = "private key to use for certificate request";
            EVP_PKEY *pkey;

            *new_pkey = KEY_load(file, pass, NULL /* engine */, desc);
            if (*new_pkey == NULL) {
                ERR_clear_error();
                desc = opt_csr == NULL
                    ? "fallback public key for cert to be enrolled"
                    : "public key for checking cert resulting from p10cr";
                pkey = FILES_load_pubkey_autofmt(file, FORMAT_PEM, pass, desc);
                if (pkey == NULL || !OSSL_CMP_CTX_set0_newPkey(ctx, 0, pkey)) {
                    EVP_PKEY_free(pkey);
                    return -41;
                }
            }
        } else if (opt_csr == NULL) {
            LOG_err("Missing -newkeytype or -centralkeygen or -newkey option");
            return -42;
        }
    }

    if (use_case == imprint || use_case == bootstrap || use_case == update) {
        if (opt_subject == NULL
                && opt_csr == NULL && opt_oldcert == NULL && opt_cert == NULL) {
            LOG_err("no -subject given for enrollment; no -csr or -oldcert or -cert available for fallback");
            return -43;
        }

        if ((err = setup_cert_template(ctx)) != CMP_OK)
            return err;
        if ((*exts = setup_X509_extensions(ctx)) == NULL) {
            LOG_err("Unable to set up X509 extensions for CMP client");
            return -44;
        }
        if (reqExtensions_have_SAN(*exts) && opt_sans != NULL) {
            LOG_err("Cannot have Subject Alternative Names both via -reqexts and via -sans");
            return CMP_R_MULTIPLE_SAN_SOURCES;
        }
        if (opt_certout == NULL) {
            LOG_err("-certout not given, nowhere to save certificate");
            return -45;
        }
    } else {
        const char *msg = "option is ignored for commands other than 'ir', 'cr', and 'kur'";

        if (opt_subject != NULL) {
            if (opt_ref == NULL && opt_cert == NULL) {
                /* use subject as default sender unless oldcert subject used */
                if ((err = set_name(opt_subject, OSSL_CMP_CTX_set1_subjectName,
                                    ctx, "subject")) != CMP_OK)
                    return err;
            } else {
                LOG(FL_WARN, "-subject %s since sender is taken from -ref or -cert",
                    msg);
            }
        }
        if (use_case != revocation && opt_issuer != NULL)
            LOG(FL_WARN, "-issuer %s", msg);
        if (opt_reqexts != NULL)
            LOG(FL_WARN, "-reqexts %s", msg);
        if (opt_san_nodefault)
            LOG(FL_WARN, "-san_nodefault %s", msg);
        if (opt_sans != NULL)
            LOG(FL_WARN, "-sans %s", msg);
        if (opt_policies != NULL)
            LOG(FL_WARN, "-policies %s", msg);
        if (opt_policy_oids != NULL)
            LOG(FL_WARN, "-policy_oids %s", msg);

        if (use_case != pkcs10) {
            if (opt_implicit_confirm)
                LOG(FL_WARN, "-implicit_confirm %s, and 'p10cr'", msg);
            if (opt_disable_confirm)
                LOG(FL_WARN, "-disable_confirm %s, and 'p10cr'", msg);
            if (opt_certout != NULL)
                LOG(FL_WARN, "-certout %s, and 'p10cr'", msg);
            if (opt_chainout != NULL)
                LOG(FL_WARN, "-chainout %s, and 'p10cr'", msg);
        }
    }
    if (use_case != revocation && opt_revreason != CRL_REASON_NONE)
        LOG_warn("-revreason option is ignored for commands other than 'rr'");
    if (use_case != update && use_case != revocation && opt_oldcert != NULL
        && !(use_case == genm && strcmp(opt_infotype, "crlStatusList") == 0))
        LOG_warn("-oldcert option used only as reference cert");

    if (opt_oldcert != NULL) {
        if (use_case == genm && strcmp(opt_infotype, "crlStatusList") != 0) {
            LOG_warn("-oldcert option is ignored for 'genm' command except with -infotype crlStatusList");
        } else {
            *oldcert = CERT_load(opt_oldcert, opt_keypass,
                                 use_case == update ? "cert to be updated" :
                                 use_case == revocation ? "cert to be revoked" :
                                 "reference certificate (oldcert)",
                                 -1 /* no type check */, vpm);
            if (*oldcert == NULL || !OSSL_CMP_CTX_set1_oldCert(ctx, *oldcert))
                return -46;
        }
    }
    if (opt_csr != NULL) {
        if (use_case == genm) {
            LOG_warn("-csr option is ignored for 'genm' command");
        } else {
            if ((*csr = CSR_load(opt_csr, "PKCS#10 CSR")) == NULL)
                return -47;
            if (!OSSL_CMP_CTX_set1_p10CSR(ctx, *csr))
                return -48;
        }
    }
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    if (use_case == revocation) {
        if (set_name(opt_issuer, OSSL_CMP_CTX_set1_issuer, ctx, "issuer") != CMP_OK)
            return -70;

        if (opt_serial != NULL) {
            ASN1_INTEGER *sno;

            if ((sno = s2i_ASN1_INTEGER(NULL, opt_serial)) == NULL) {
                LOG(FL_ERR, "cannot read serial number: '%s'", opt_serial);
                return -71;
            }
            if (!OSSL_CMP_CTX_set1_serialNumber(ctx, sno)) {
                ASN1_INTEGER_free(sno);
                LOG_err("out of memory");
                return -72;
            }
            ASN1_INTEGER_free(sno);
        }
    }
#endif
    return CMP_OK;
}

#if OPENSSL_VERSION_NUMBER >= 0x30200000L || defined USE_LIBCMP
static int delete_file(const char *file, const char *desc)
{
    if (file == NULL)
        return 1;
    LOG(FL_INFO, "deleting file '%s' because there is no %s", file, desc);
    if (unlink(file) == 0 || errno == ENOENT)
        return 1;
    LOG(FL_ERR, "Failed to delete %s, which should be done to indicate there is no %s",
        file, desc);
    return 0;
}

static int save_cert_or_delete(X509 *cert, const char *file, const char *desc)
{
    if (file == NULL)
        return 1;
    if (cert == NULL)
        return delete_file(file, desc);
    return CERT_save(cert, file, desc) ? 1 : 0;
}
#endif

static
CMP_err save_certs(STACK_OF(X509) *certs, const char *field, const char *desc,
                   const char *file, const char *dir, const char *format)
{
    char desc_certs[80];

    snprintf(desc_certs, sizeof(desc_certs), "%s certs", desc);
    LOG(FL_TRACE, "Extracted %s from %s", desc_certs, field);

    if (file != NULL) {
        if (CERTS_save(certs, file, desc_certs) < 0) {
            LOG(FL_ERR, "Failed to store %s from %s in %s",
                desc_certs, field, file);
            CERTS_free(certs);
            return -49;
        }
    }

    if (dir != NULL) {
        if (sk_X509_num(certs) <= 0)
            LOG(FL_INFO, "No %s certificate in %s to store in %s",
                desc, field, dir);
        int i;
        for (i = 0; i < sk_X509_num(certs); i++) {
            X509 *cert = sk_X509_value(certs, i);
            bool save_self_issued = strcmp(field, "caPubs") == 0;

            if ((X509_check_issued(cert, cert) == X509_V_OK)
                != save_self_issued) {
                LOG(FL_WARN, "%s cert #%d in %s is%s self-issued and not stored",
                    desc, i + 1, field, save_self_issued ? " not" : "");
            } else {
                char path[FILENAME_MAX];

                if (get_cert_filename(cert, dir, format, path,
                                      sizeof(path)) == 0
                    || !FILES_store_cert(cert, path, FILES_get_format(format),
                                         desc_certs)) {
                    LOG(FL_ERR, "Failed to store %s cert #%d from %s in %s",
                        desc, i + 1, field, dir);
                    CERTS_free(certs);
                    return -52;
                }
            }
        }
    }
    CERTS_free(certs);
    return CMP_OK;
}

static CMP_err save_credentials(CMP_CTX *ctx, CREDENTIALS *new_creds,
                                enum use_case use_case)
{
    CMP_err err = save_certs(OSSL_CMP_CTX_get1_extraCertsIn(ctx),
                             "extraCerts", "extra", opt_extracertsout,
                             opt_extracerts_dir, opt_extracerts_dir_format);

    if (err != CMP_OK)
        return err;

    if (use_case == revocation || use_case == genm || use_case == validate)
        return CMP_OK;

    err = save_certs(OSSL_CMP_CTX_get1_caPubs(ctx), "caPubs", "CA",
                     opt_cacertsout, opt_cacerts_dir, opt_cacerts_dir_format);
    if (err != CMP_OK)
        return err;

    if (use_case != pkcs10 && opt_newkey != NULL
            && (opt_newkeytype != NULL || opt_centralkeygen)) {
        const char *new_desc = "newly enrolled certificate and related chain and key";

        if (opt_chainout != NULL)
            LOG_warn("-chainout option is ignored");

        if (!CREDENTIALS_save(new_creds, opt_certout,
                              opt_newkey, opt_newkeypass, new_desc)) {
            LOG_err("Failed to save newly enrolled credentials");
            return CMP_R_STORE_CREDS; /* unused: -54 */
        }
    } else {
        X509 *cert = CREDENTIALS_get_cert(new_creds);
        STACK_OF(X509) *certs = CREDENTIALS_get_chain(new_creds);

        if (opt_chainout != NULL && strcmp(opt_chainout, opt_certout) != 0) {
            if (!CERT_save(cert, opt_certout, "newly enrolled certificate")) {
                return CMP_R_STORE_CREDS;
            }
            if (opt_chainout != NULL &&
                CERTS_save(certs, opt_chainout,
                           "chain of newly enrolled certificate") < 0) {
                return CMP_R_STORE_CREDS;
            }
        } else {
            if (!FILES_store_credentials(NULL /* key */, cert, certs, NULL,
                                         opt_certout, FORMAT_PEM, NULL,
                                         "newly enrolled certificate and chain"))
                return CMP_R_STORE_CREDS;
        }
    }
    return CMP_OK;
}

static int print_itavs(const STACK_OF(OSSL_CMP_ITAV) *itavs)
{
    int i, ret = 1;
    int n = sk_OSSL_CMP_ITAV_num(itavs);

    if (n <= 0) { /* also in case itavs == NULL */
        LOG(FL_INFO, "genp does not contain any ITAV");
        return ret;
    }

    for (i = 1; i <= n; i++) {
        OSSL_CMP_ITAV *itav = sk_OSSL_CMP_ITAV_value(itavs, i - 1);
        ASN1_OBJECT *type = OSSL_CMP_ITAV_get0_type(itav);
        char name[80];

        if (itav == NULL) {
            LOG(FL_ERR, "could not get ITAV #%d from genp", i);
            ret = 0;
            continue;
        }
        if (i2t_ASN1_OBJECT(name, sizeof(name), type) <= 0) {
            LOG(FL_ERR, "error parsing type of ITAV #%d from genp", i);
            ret = 0;
        } else {
            LOG(FL_INFO, "ITAV #%d from genp type=%s", i, name);
        }
    }
    return ret;
}

#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
static int save_template(const char *file, const OSSL_CRMF_CERTTEMPLATE *tmpl)
{
    BIO *bio = BIO_new_file(file, "wb");
    CMP_err res = CMP_OK;

    if (bio == NULL) {
        LOG(FL_ERR, "error saving certTemplate from genp: cannot open file %s",
            file);
        return -55;
    }
    if (!ASN1_i2d_bio_of(OSSL_CRMF_CERTTEMPLATE, i2d_OSSL_CRMF_CERTTEMPLATE,
                         bio, tmpl)) {
        LOG(FL_ERR, "error saving certTemplate from genp: cannot write file %s",
            file);
        res = -56;
    } else {
        LOG(FL_INFO, "stored certTemplate from genp to file '%s'", file);
    }
    BIO_free(bio);
    return res;
}

static const char *nid_name(int nid)
{
    const char *name = OBJ_nid2ln(nid);

    if (name == NULL)
        name = OBJ_nid2sn(nid);
    if (name == NULL)
        name = "<unknown OID>";
    return name;
}
#endif

static CMP_err do_genm(CMP_CTX *ctx, X509 *oldcert)
{
    CMP_err err;

    switch (infotype) {
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    case NID_id_it_caCerts:
        if (opt_cacertsout == NULL) {
            LOG(FL_ERR, "Missing -cacertsout option for -infotype caCerts");
            return -57;
        }

        STACK_OF(X509) *cacerts = NULL;
        err = CMPclient_caCerts(ctx, &cacerts);

        if (err == CMP_OK) {
            /* TODO possibly check authorization of sender/origin */
            if (cacerts == NULL)
                LOG_warn("no CA certificate provided by server");
            if (CERTS_save(cacerts, opt_cacertsout, "caCerts from genp") < 0) {
                LOG(FL_ERR, "Failed to store CA certificates from genp in %s",
                    opt_cacertsout);
                err = -58;
            }
        }
        CERTS_free(cacerts);
        return err;
#endif
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    case NID_id_it_rootCaCert:
        if (opt_newwithnew == NULL) {
            LOG(FL_ERR, "Missing -newwithnew option for -infotype rootCaCert");
            return -59;
        }
        {
            X509 *oldwithold = NULL;
            X509 *newwithnew = NULL;
            X509 *newwithold = NULL;
            X509 *oldwithnew = NULL;

            err = -60;
            if (opt_oldwithold == NULL) {
                LOG(FL_WARN, "No -oldwithold given, will use all certs given with -trusted as trust anchors for verifying the newWithNew cert");
            } else {
                oldwithold = CERT_load(opt_oldwithold, NULL,
                                       "OldWithOld cert for genm with -infotype rootCaCert",
                                       1 /* CA */, NULL /* vpm */);
                if (oldwithold == NULL)
                    goto end_upd;
            }
            err = CMPclient_rootCaCert(ctx, oldwithold, &newwithnew,
                                       &newwithold, &oldwithnew);
            if (err != CMP_OK)
                goto end_upd;

            /* TODO possibly check authorization of sender/origin */
            if (newwithnew == NULL)
                LOG_info("no root CA certificate update available");
            if (!save_cert_or_delete(newwithnew, opt_newwithnew,
                                     "NewWithNew cert from genp")
                || !save_cert_or_delete(newwithold, opt_newwithold,
                                        "NewWithOld cert from genp")
                || !save_cert_or_delete(oldwithnew, opt_oldwithnew,
                                        "OldWithNew cert from genp"))
                err = -61;

            X509_free(newwithnew);
            X509_free(newwithold);
            X509_free(oldwithnew);
        end_upd:
            X509_free(oldwithold);
            return err;
        }

    case NID_id_it_crlStatusList:
        if (opt_oldcrl == NULL && opt_oldcert == NULL) {
            LOG(FL_ERR, "Missing -oldcrl and no -oldcert given for -infotype crlStatusList");
            return -62;
        }
        if (opt_crlout == NULL) {
            LOG(FL_ERR, "Missing -crlout for -infotype crlStatusList");
            return -63;
        }
        {
            X509_CRL *oldcrl = NULL, *crl = NULL;

            err = -64;
            if (opt_oldcrl == NULL) {
                LOG(FL_WARN, "No -oldcrl given, will use data from -oldcert");
            } else {
                oldcrl = CRL_load(opt_oldcrl, (int)opt_crls_timeout,
                                  "CRL for genm with -infotype crlStatusList");
                if (oldcrl == NULL)
                    goto end_crlupd;
            }
            err = CMPclient_crlUpdate(ctx, oldcert, oldcrl, &crl);
            if (err != CMP_OK)
                goto end_crlupd;

            const char *desc = "CRL from genp of type 'crls'";
            if (crl == NULL) {
                LOG_info("no CRL update available");
                if (!delete_file(opt_crlout, desc))
                    err = -65;
            } else if (!FILES_store_crl(crl, opt_crlout, FORMAT_ASN1, desc)) {
                err = -66;
            }
        end_crlupd:
            X509_CRL_free(oldcrl);
            X509_CRL_free(crl);
            return err;
        }

    case NID_id_it_certReqTemplate:
        if (opt_template == NULL) {
            LOG(FL_ERR, "Missing -template option for -infotype certReqTemplate");
            return -67;
        }

        OSSL_CRMF_CERTTEMPLATE *certTemplate;
        OSSL_CMP_ATAVS *keySpec;
        err = CMPclient_certReqTemplate(ctx, &certTemplate, &keySpec);

        if (err != CMP_OK)
            return err;
        if (certTemplate == NULL) {
            LOG_warn("no certificate request template available");
            if (!delete_file(opt_template, "certTemplate from genp"))
                return -68;
            return CMP_OK;
        }
        err = save_template(opt_template, certTemplate);
        OSSL_CRMF_CERTTEMPLATE_free(certTemplate);
        if (err != CMP_OK || keySpec == NULL)
            goto tmpl_end;

        const char *desc = "specifications contained in keySpec from genp";
        BIO *mem = BIO_new(BIO_s_mem());
        if (mem == NULL) {
            LOG(FL_ERR, "Out of memory - cannot dump key %s", desc);
            goto tmpl_end;
        }
        BIO_printf(mem, "Key %s:\n", desc);

        int i, n = sk_OSSL_CMP_ATAV_num(keySpec);
        for (i = 0; i < n; i++) {
            OSSL_CMP_ATAV *atav = sk_OSSL_CMP_ATAV_value(keySpec, i);
            ASN1_OBJECT *type = OSSL_CMP_ATAV_get0_type(atav /* may be NULL */);
            int nid = OBJ_obj2nid(type);

            switch (nid) {
            case NID_id_regCtrl_algId:
                {
                    X509_ALGOR *alg = OSSL_CMP_ATAV_get0_algId(atav);
                    const ASN1_OBJECT *oid;
                    int paramtype;
                    const void *param;

                    X509_ALGOR_get0(&oid, &paramtype, &param, alg);
                    BIO_printf(mem, "Key algorithm: ");
                    i2a_ASN1_OBJECT(mem, oid);
                    if (paramtype == V_ASN1_UNDEF || alg->parameter == NULL) {
                        BIO_printf(mem, "\n");
                    } else {
                        BIO_printf(mem, " - ");
                        ASN1_item_print(mem, (ASN1_VALUE *)alg,
                                        0, ASN1_ITEM_rptr(X509_ALGOR), NULL);
                    }
                }
                break;
            case NID_id_regCtrl_rsaKeyLen:
                BIO_printf(mem, "Key algorithm: RSA %d bit\n",
                           OSSL_CMP_ATAV_get_rsaKeyLen(atav));
                break;
            default:
                BIO_printf(mem, "Invalid key spec: %s\n", nid_name(nid));
                break;
            }
        }
        BIO_printf(mem, "End of key %s", desc);

        const char *p;
        long len = BIO_get_mem_data(mem, &p);
        if (len > INT_MAX)
            LOG(FL_ERR, "Info too large - cannot dump key %s", desc);
        else
            LOG(FL_INFO, "%.*s", (int)len, p);
        BIO_free(mem);
    tmpl_end:
        sk_OSSL_CMP_ATAV_pop_free(keySpec, OSSL_CMP_ATAV_free);
        return err;
#else
    case -1:
        err = oldcert == NULL ? 0 : 0;
        return err;
#endif

    default:
        if (infotype != NID_undef) {
            OSSL_CMP_ITAV *req =
                OSSL_CMP_ITAV_create(OBJ_nid2obj(infotype), NULL);

            LOG(FL_WARN, "No specific support for -infotype %s available",
                opt_infotype);
            if (req == NULL || !OSSL_CMP_CTX_push0_genm_ITAV(ctx, req)) {
                LOG(FL_ERR, "Failed to create genm for -infotype %s",
                         opt_infotype);
                return -24;
            }
        }

        STACK_OF(OSSL_CMP_ITAV) *itavs = OSSL_CMP_exec_GENM_ses(ctx);
        if (itavs != NULL) {
            int res = print_itavs(itavs);

            sk_OSSL_CMP_ITAV_pop_free(itavs, OSSL_CMP_ITAV_free);
            return res ? CMP_OK : -25;
        }
        if (OSSL_CMP_CTX_get_status(ctx) != OSSL_CMP_PKISTATUS_request)
            LOG(FL_ERR, "Did not receive response on genm or genp is not valid");
        return -26;
    }
}

static int CMPclient(enum use_case use_case, OPTIONAL LOG_cb_t log_fn)
{
    CMP_err err = -01;
    CMP_CTX *ctx = NULL;
    EVP_PKEY *new_pkey = NULL;
    X509_EXTENSIONS *exts = NULL;
    CREDENTIALS *new_creds = NULL;
    X509 *oldcert = NULL;
    X509_REQ *csr = NULL;

    if ((err = complete_genm_asn1_objects()) != CMP_OK)
        goto err;
    if ((err = check_options(use_case)) != CMP_OK)
        goto err;
    if ((err = prepare_CMP_client(&ctx, use_case, log_fn)) != CMP_OK) {
        LOG_err("Failed to prepare CMP client");
        goto err;
    }
    if ((err = setup_ctx(ctx)) != CMP_OK) {
        LOG_err("Failed to prepare CMP client");
        goto err;
    }
    if ((err = check_template_options(ctx, &new_pkey, &oldcert, &csr,
                                      &exts, use_case)) != CMP_OK)
        goto err;

    if (opt_revreason < CRL_REASON_NONE
        || opt_revreason > CRL_REASON_AA_COMPROMISE
        || opt_revreason == 7) {
        LOG_err("Invalid revreason given. Valid values are -1..6, 8..10");
        err = -27;
        goto err;
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
        err = CMPclient_pkcs10(ctx, &new_creds, csr);
        break;
    case update:
        if (opt_oldcert == NULL)
            err = CMPclient_update(ctx, &new_creds, new_pkey);
        else
            err = CMPclient_update_anycert(ctx, &new_creds, oldcert, new_pkey);
        break;
    case revocation:
        err = CMPclient_revoke(ctx, oldcert, (int)opt_revreason);
        break;
    case genm:
        err = do_genm(ctx, oldcert);
        break;
    default:
        LOG(FL_ERR, "Unknown use case '%d' used", use_case);
        err = -19;
    }

    int status = OSSL_CMP_CTX_get_status(ctx);
    if (err != -19 && use_case != genm && status >= 0) {
        /* we got some response, print PKIStatusInfo */
        char buf[OSSL_CMP_PKISI_BUFLEN];
        char *string = CMPclient_snprint_PKIStatus(ctx, buf, sizeof(buf));
        const char *from = "", *server = "";

        if (opt_server != NULL) {
            from = " from ";
            server = opt_server;
        }
        LOG(LOG_FUNC_FILE_LINE,
            status == OSSL_CMP_PKISTATUS_accepted
            ? LOG_INFO :
            status == OSSL_CMP_PKISTATUS_rejection
            || status == OSSL_CMP_PKISTATUS_waiting
            ? LOG_ERR : LOG_WARNING,
            "received%s%s %s", from, server,
            string != NULL ? string : "<unknown PKIStatus>");
    }

#if OPENSSL_VERSION_NUMBER >= 0x30200000L || defined USE_LIBCMP
    if (!save_cert_or_delete(OSSL_CMP_CTX_get0_validatedSrvCert(ctx),
                             opt_srvcertout, "validated server cert"))
        err = -53;
#endif
    if (err != CMP_OK) {
        LOG_err("Failed to perform CMP transaction");
        goto err;
    }

    err = save_credentials(ctx, new_creds, use_case);

 err:
    CMPclient_finish(ctx); /* this also frees ctx */
    KEY_free(new_pkey);
    EXTENSIONS_free(exts);
    CREDENTIALS_free(new_creds);
    X509_free(oldcert);
    X509_REQ_free(csr);

    LOG_close();
    if (err != CMP_OK) {
        const char *reason;

        switch (err) {
        case CMP_R_LOAD_CERTS:
            reason = "error loading certificates";
            break;
        case CMP_R_LOAD_CREDS:
            reason = "error loading credentials";
            break;
        case CMP_R_GENERATE_KEY:
            reason = "error generating key";
            break;
        case CMP_R_STORE_CREDS:
            reason = "error storing credentials";
            break;
        case CMP_R_RECIPIENT:
            reason = "error setting up recipient";
            break;
        case CMP_R_INVALID_CONTEXT:
            reason = "invalid context ";
            break;
        default:
            reason = ERR_reason_error_string(ERR_PACK(ERR_LIB_CMP, 0, err));
        }
        if (err < 100 || reason == NULL)
            LOG(FL_ERR, "CMPclient error %d", err);
        else
            LOG(FL_ERR, "CMPclient error %d: %s", err, reason);
    }
    return err;
}

static int print_help(const char *prog)
{
    BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_stdout, "Usage:\n"
               "%s (imprint | bootstrap | pkcs10 | update | revoke | genm | validate) [-section <server>]\n"
               "%s options\n\n"
               "Available options are:\n",
               prog, prog);
    OPT_help(cmp_opts, bio_stdout);
    BIO_free(bio_stdout);
    return EXIT_SUCCESS;
}

static bool set_verbosity(long level)
{
    if (level < LOG_EMERG || level > LOG_TRACE) {
        LOG(FL_ERR, "Logging verbosity level %d out of range (0 .. 8)", level);
        return false;
    }
    opt_verbosity = level;
    LOG_set_verbosity((severity)level);
    return true;
}

int main(int argc, char *argv[])
{
    int i;
    int rv, rc = EXIT_FAILURE;
    const char *name = "cmpClient";
    LOG_cb_t log_fn = LOG_console;

    if (CMPclient_init(name, log_fn) != CMP_OK)
        goto end;

    enum use_case use_case = no_use_case; /* default */
    if (argc > 1) {
        if (strcmp(argv[1], "imprint") == 0) {
            use_case = imprint;
        } else if (strcmp(argv[1], "bootstrap") == 0) {
            use_case = bootstrap;
        } else if (strcmp(argv[1], "pkcs10") == 0) {
            use_case = pkcs10;
        } else if (strcmp(argv[1], "update") == 0) {
            use_case = update;
        } else if (strcmp(argv[1], "revoke") == 0) {
            use_case = revocation;
        } else if (strcmp(argv[1], "genm") == 0) {
            use_case = genm;
        } else if (strcmp(argv[1], "validate") == 0) {
            use_case = validate;
        }
    }

    if (!OPT_init(cmp_opts))
        goto end;
    /*
     * handle -help, -config, -section, and -verbosity upfront
     * to take effect for other opts
     */
    const char *prog = argv[0];
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (argv[i][1] == '-')
                argv[i]++;
            if (strcmp(argv[i] + 1, "help") == 0) {
                rc = print_help(prog);
                goto end;
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
        snprintf(demo_sections, sizeof(demo_sections),
                 "%s,%s", opt_section, argv[1]);
        opt_section = demo_sections;
    }

    if (opt_config != NULL) {
        LOG(FL_INFO, "Using section(s) '%s' of CMP configuration file '%s'",
            opt_section, opt_config);
        config = CONF_load_options(NULL, opt_config, opt_section, cmp_opts);
        if (config == NULL)
            goto end;
    }
    vpm = X509_VERIFY_PARAM_new();
    if (vpm == 0) {
        LOG_err("Out of memory");
        goto end;
    }
    cmdata = CRLMGMT_DATA_new();
    if (cmdata == 0) {
        LOG_err("Out of memory");
        goto end;
    }
    if (config != NULL && !CONF_update_vpm(config, opt_section, vpm))
        goto end;
    argv++;
    if (use_case != no_use_case)
        argv++; /* skip first option since use_case is given */
    rv = OPT_read(cmp_opts, argv, vpm);
    if (rv == -1) {
        /* can only happen for ---help as [-]-help has already been handled */
        rc = print_help(prog);
        goto end;
    }
    if (rv <= 0)
        goto end;
    if (!set_verbosity(opt_verbosity))
        goto end;

    CRLMGMT_DATA_set_proxy_url(cmdata, opt_cdp_proxy);
    CRLMGMT_DATA_set_crl_max_download_size(cmdata, opt_crl_maxdownload_size);
    CRLMGMT_DATA_set_crl_cache_dir(cmdata, opt_crl_cache_dir);
    CRLMGMT_DATA_set_note(cmdata, use_case == validate ? "validation" :
                          "tls or cmp connection or new certificate");

    /* handle here to start correct demo use case */
    if (opt_cmd != NULL) {
        if (use_case == validate) {
            LOG_err("-cmd option cannot be combined with 'validate' use case");
            goto end;
        }
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

    if (opt_crls != NULL) {
        crls = CRLs_load(opt_crls, (int)opt_crls_timeout, "pre-determined CRLs");
        if (crls == NULL)
            goto end;
    }
    if (use_case == validate ? validate_cert()
                             : CMPclient(use_case, log_fn) == CMP_OK)
        rc = EXIT_SUCCESS;
    CRLs_free(crls);

 end:
    if (rc != EXIT_SUCCESS)
        OSSL_CMP_CTX_print_errors(NULL);
    CRLMGMT_DATA_free(cmdata);
    X509_VERIFY_PARAM_free(vpm);
    /* TODO fix potential memory leaks; find out why this potentially crashes: */
    NCONF_free(config);

    return rc;
}
