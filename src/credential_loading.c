/*-
 * @file   credential_loading.c
 * @brief  generic CMP client CLI helper functions like in OpenSSL apps
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright 2007-2025 The OpenSSL Project Authors. All Rights Reserved.
 *  Copyright (c) 2025 Siemens AG
 *
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/core_names.h>
#include <secutils/credentials/credentials.h>
#include <secutils/credentials/store.h>
#include <secutils/credentials/cert.h>
#include <secutils/connections/conn.h> /* for CONN_IS_HTTP[S] */
#include <secutils/util/log.h>

#include "credential_loading.h"

/* from OpenSSL/apps/lib/app_libctx.c: */
static OSSL_LIB_CTX *app_libctx = NULL;
static const char *app_propq = NULL;

const char *app_get0_propq(void)
{
    return app_propq;
}

OSSL_LIB_CTX *app_get0_libctx(void)
{
    return app_libctx;
}

/* from OpenSSL/apps/lib/app_provider.c: */

DEFINE_STACK_OF(OSSL_PROVIDER)
static STACK_OF(OSSL_PROVIDER) *app_providers = NULL;

static void provider_free(OSSL_PROVIDER *prov)
{
    OSSL_PROVIDER_unload(prov);
}

void app_providers_cleanup(void)
{
    sk_OSSL_PROVIDER_pop_free(app_providers, provider_free);
    app_providers = NULL;
}

int opt_provider_path(const char *path)
{
    if (path != NULL && *path == '\0')
        path = NULL;
    return OSSL_PROVIDER_set_default_search_path(app_libctx, path);
}

int app_provider_load(const char *provider_name)
{
    OSSL_PROVIDER *prov;

    prov = OSSL_PROVIDER_load(app_libctx, provider_name);
    if (prov == NULL) {
        LOG(FL_ERR, "unable to load provider %s\n"
            "Hint: use -provider-path option or OPENSSL_MODULES environment variable.\n",
            provider_name);
        ERR_print_errors(bio_err);
        return 0;
    }
    if (app_providers == NULL)
        app_providers = sk_OSSL_PROVIDER_new_null();
    if (app_providers == NULL
        || !sk_OSSL_PROVIDER_push(app_providers, prov)) {
        app_providers_cleanup();
        return 0;
    }
    return 1;
}

/* mostly from OpenSSL/apps/lib/apps_ui.c: */

#include <openssl/ui.h>

static UI_METHOD *ui_method = NULL;
static const UI_METHOD *ui_base_method = NULL;

#define PW_MIN_LENGTH 4
typedef struct pw_cb_data {
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;

static int ui_open(UI *ui)
{
    int (*opener)(UI *ui) = UI_method_get_opener(ui_base_method);

    if (opener != NULL)
        return opener(ui);
    return 1;
}

static int ui_read(UI *ui, UI_STRING *uis)
{
    int (*reader)(UI *ui, UI_STRING *uis) = NULL;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;

                if (password != NULL)
                    UI_set_result(ui, uis, password);
                return 1; /* also on password == NULL */
            }
            break;
        case UIT_NONE:
        case UIT_BOOLEAN:
        case UIT_INFO:
        case UIT_ERROR:
            break;
        }
    }

    reader = UI_method_get_reader(ui_base_method);
    if (reader != NULL)
        return reader(ui, uis);
    /* Default to the empty password if we've got nothing better */
    UI_set_result(ui, uis, "");
    return 1;
}

static int ui_write(UI *ui, UI_STRING *uis)
{
    int (*writer)(UI *ui, UI_STRING *uis) = NULL;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;

                if (password != NULL)
                    return 1;
            }
            break;
        case UIT_NONE:
        case UIT_BOOLEAN:
        case UIT_INFO:
        case UIT_ERROR:
            break;
        }
    }

    writer = UI_method_get_writer(ui_base_method);
    if (writer != NULL)
        return writer(ui, uis);
    return 1;
}

static int ui_close(UI *ui)
{
    int (*closer)(UI *ui) = UI_method_get_closer(ui_base_method);

    if (closer != NULL)
        return closer(ui);
    return 1;
}

/* object_name defaults to prompt_info from ui user data if present */
static char *ui_prompt_construct(UI *ui, const char *phrase_desc,
                                 const char *object_name)
{
    PW_CB_DATA *cb_data = (PW_CB_DATA *)UI_get0_user_data(ui);

    if (phrase_desc == NULL)
        phrase_desc = "pass phrase";
    if (object_name == NULL && cb_data != NULL)
        object_name = cb_data->prompt_info;
    return UI_construct_prompt(NULL, phrase_desc, object_name);
}

int set_base_ui_method(const UI_METHOD *ui_meth)
{
    if (ui_meth == NULL)
        ui_meth = UI_null();
    ui_base_method = ui_meth;
    return 1;
}

int setup_ui_method(void)
{
    ui_base_method = UI_null();
#ifndef OPENSSL_NO_UI_CONSOLE
    ui_base_method = UI_OpenSSL();
#endif
    ui_method = UI_create_method("OpenSSL application user interface");
    return ui_method != NULL
        && 0 == UI_method_set_opener(ui_method, ui_open)
        && 0 == UI_method_set_reader(ui_method, ui_read)
        && 0 == UI_method_set_writer(ui_method, ui_write)
        && 0 == UI_method_set_closer(ui_method, ui_close)
        && 0 == UI_method_set_prompt_constructor(ui_method,
                                                 ui_prompt_construct);
}

void destroy_ui_method(void)
{
    if (ui_method != NULL) {
        UI_destroy_method(ui_method);
        ui_method = NULL;
    }
}

static const UI_METHOD *get_ui_method(void)
{
    return ui_method;
}

/* from OpenSSL/apps/lib/apps.c: */

static const char *format2string(int format)
{
    switch (format) {
    case FORMAT_PEM:
        return "PEM";
    case FORMAT_ASN1:
        return "DER";
    }
    return NULL;
}

static void unbuffer(FILE *fp)
{
/*
 * On VMS, setbuf() will only take 32-bit pointers, and a compilation
 * with /POINTER_SIZE=64 will give off a MAYLOSEDATA2 warning here.
 * However, we trust that the C RTL will never give us a FILE pointer
 * above the first 4 GB of memory, so we simply turn off the warning
 * temporarily.
 */
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma environment save
# pragma message disable maylosedata2
#endif
    setbuf(fp, NULL);
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma environment restore
#endif
}

/* Set type expectation, but set to 0 if objects of multiple types expected. */
#define SET_EXPECT(val) \
    (expect = expect < 0 ? (val) : (expect == (val) ? (val) : 0))
#define SET_EXPECT1(pvar, val) \
    if ((pvar) != NULL) { \
        *(pvar) = NULL; \
        SET_EXPECT(val); \
    }
/* Provide (error msg) text for some of the credential types to be loaded. */
#define FAIL_NAME \
    (ppkey != NULL ? "private key" : ppubkey != NULL ? "public key" :  \
     pparams != NULL ? "key parameters" :                              \
     pcert != NULL ? "certificate" : pcerts != NULL ? "certificates" : \
     pcrl != NULL ? "CRL" : pcrls != NULL ? "CRLs" : NULL)
/*
 * Load those types of credentials for which the result pointer is not NULL.
 * Reads from stdin if 'uri' is NULL and 'maybe_stdin' is nonzero.
 * 'format' parameter may be FORMAT_PEM, FORMAT_ASN1, or 0 for no hint.
 * desc may contain more detail on the credential(s) to be loaded for error msg
 * For non-NULL ppkey, pcert, and pcrl the first suitable value found is loaded.
 * If pcerts is non-NULL and *pcerts == NULL then a new cert list is allocated.
 * If pcerts is non-NULL then all available certificates are appended to *pcerts
 * except any certificate assigned to *pcert.
 * If pcrls is non-NULL and *pcrls == NULL then a new list of CRLs is allocated.
 * If pcrls is non-NULL then all available CRLs are appended to *pcerts
 * except any CRL assigned to *pcrl.
 * In any case (also on error) the caller is responsible for freeing all members
 * of *pcerts and *pcrls (as far as they are not NULL).
 */

static
bool load_key_certs_crls(OSSL_LIB_CTX *libctx, const char *propq,
                         const char *uri, int format, bool maybe_stdin,
                         const char *pass, const char *desc, bool quiet,
                         EVP_PKEY **ppkey, EVP_PKEY **ppubkey,
                         EVP_PKEY **pparams,
                         X509 **pcert, STACK_OF(X509) **pcerts,
                         X509_CRL **pcrl, STACK_OF(X509_CRL) **pcrls)
{
    PW_CB_DATA ui_data = {pass, uri};
    OSSL_STORE_CTX *ctx = NULL;
    int ncerts = 0, ncrls = 0, expect = -1;
    const char *failed = FAIL_NAME;
    const char *input_type;
    OSSL_PARAM itp[2];
    const OSSL_PARAM *params = NULL;

    /* 'failed' describes type of credential to load for potential error msg */
    if (failed == NULL) {
        if (!quiet)
            BIO_printf(bio_err, "Internal error: nothing was requested to load from %s\n",
                       uri != NULL ? uri : "<stdin>");
        return 0;
    }
    /* suppress any extraneous errors left over from failed parse attempts */
    ERR_set_mark();

    SET_EXPECT1(ppkey, OSSL_STORE_INFO_PKEY);
    SET_EXPECT1(ppubkey, OSSL_STORE_INFO_PUBKEY);
    SET_EXPECT1(pparams, OSSL_STORE_INFO_PARAMS);
    SET_EXPECT1(pcert, OSSL_STORE_INFO_CERT);
    /*
     * Up to here, the follwing holds.
     * If just one of the ppkey, ppubkey, pparams, and pcert function parameters
     * is nonzero, expect > 0 indicates which type of credential is expected.
     * If expect == 0, more than one of them is nonzero (multiple types expected).
     */

    if (pcerts != NULL) {
        if (*pcerts == NULL && (*pcerts = sk_X509_new_null()) == NULL) {
            if (!quiet)
                BIO_printf(bio_err, "Out of memory loading");
            goto end;
        }
        /*
         * Adapt the 'expect' variable:
         * set to OSSL_STORE_INFO_CERT if no other type is expected so far,
         * otherwise set to 0 (indicating that multiple types are expected).
         */
        SET_EXPECT(OSSL_STORE_INFO_CERT);
    }
    SET_EXPECT1(pcrl, OSSL_STORE_INFO_CRL);
    if (pcrls != NULL) {
        if (*pcrls == NULL && (*pcrls = sk_X509_CRL_new_null()) == NULL) {
            if (!quiet)
                BIO_printf(bio_err, "Out of memory loading");
            goto end;
        }
        /*
         * Adapt the 'expect' variable:
         * set to OSSL_STORE_INFO_CRL if no other type is expected so far,
         * otherwise set to 0 (indicating that multiple types are expected).
         */
        SET_EXPECT(OSSL_STORE_INFO_CRL);
    }

    if ((input_type = format2string(format)) != NULL) {
        itp[0] = OSSL_PARAM_construct_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE,
                                                  (char *)input_type, 0);
        itp[1] = OSSL_PARAM_construct_end();
        params = itp;
    }

    if (uri == NULL) {
        BIO *bio;

        if (!maybe_stdin) {
            if (!quiet)
                BIO_printf(bio_err, "No filename or uri specified for loading\n");
            goto end;
        }
        uri = "<stdin>";
        unbuffer(stdin);
        bio = BIO_new_fp(stdin, 0);
        if (bio != NULL) {
            ctx = OSSL_STORE_attach(bio, "file", libctx, propq,
                                    get_ui_method(), &ui_data, params,
                                    NULL, NULL);
            BIO_free(bio);
        }
    } else {
        ctx = OSSL_STORE_open_ex(uri, libctx, propq, get_ui_method(), &ui_data,
                                 params, NULL, NULL);
    }
    if (ctx == NULL) {
        if (!quiet)
            BIO_printf(bio_err, "Could not open file or uri for loading");
        goto end;
    }
    /* expect == 0 means here multiple types of credentials are to be loaded */
    if (expect > 0 && !OSSL_STORE_expect(ctx, expect)) {
        if (!quiet)
            BIO_printf(bio_err, "Internal error trying to load");
        goto end;
    }

    failed = NULL;
    /* from here, failed != NULL only if actually an error has been detected */

    while ((ppkey != NULL || ppubkey != NULL || pparams != NULL
            || pcert != NULL || pcerts != NULL || pcrl != NULL || pcrls != NULL)
           && !OSSL_STORE_eof(ctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
        int type, ok = 1;

        /*
         * This can happen (for example) if we attempt to load a file with
         * multiple different types of things in it - but the thing we just
         * tried to load wasn't one of the ones we wanted, e.g. if we're trying
         * to load a certificate but the file has both the private key and the
         * certificate in it. We just retry until eof.
         */
        if (info == NULL)
            continue;

        type = OSSL_STORE_INFO_get_type(info);
        switch (type) {
        case OSSL_STORE_INFO_PKEY:
            if (ppkey != NULL) {
                ok = (*ppkey = OSSL_STORE_INFO_get1_PKEY(info)) != NULL;
                if (ok)
                    ppkey = NULL;
                break;
            }
            /*
             * An EVP_PKEY with private parts also holds the public parts,
             * so if the caller asked for a public key, and we got a private
             * key, we can still pass it back.
             */
            /* fall through */
        case OSSL_STORE_INFO_PUBKEY:
            if (ppubkey != NULL) {
                ok = (*ppubkey = OSSL_STORE_INFO_get1_PUBKEY(info)) != NULL;
                if (ok)
                    ppubkey = NULL;
            }
            break;
        case OSSL_STORE_INFO_PARAMS:
            if (pparams != NULL) {
                ok = (*pparams = OSSL_STORE_INFO_get1_PARAMS(info)) != NULL;
                if (ok)
                    pparams = NULL;
            }
            break;
        case OSSL_STORE_INFO_CERT:
            if (pcert != NULL) {
                ok = (*pcert = OSSL_STORE_INFO_get1_CERT(info)) != NULL;
                if (ok)
                    pcert = NULL;
            } else if (pcerts != NULL) {
                ok = X509_add_cert(*pcerts,
                                   OSSL_STORE_INFO_get1_CERT(info),
                                   X509_ADD_FLAG_DEFAULT);
            }
            ncerts += ok;
            break;
        case OSSL_STORE_INFO_CRL:
            if (pcrl != NULL) {
                ok = (*pcrl = OSSL_STORE_INFO_get1_CRL(info)) != NULL;
                if (ok)
                    pcrl = NULL;
            } else if (pcrls != NULL) {
                ok = sk_X509_CRL_push(*pcrls, OSSL_STORE_INFO_get1_CRL(info));
            }
            ncrls += ok;
            break;
        default:
            /* skip any other type; ok stays == 1 */
            break;
        }
        OSSL_STORE_INFO_free(info);
        if (!ok) {
            failed = OSSL_STORE_INFO_type_string(type);
            if (!quiet)
                BIO_printf(bio_err, "Error reading");
            break;
        }
    }

 end:
    OSSL_STORE_close(ctx);

    /* see if any of the requested types of credentials was not found */
    if (failed == NULL) {
        if (ncerts > 0)
            pcerts = NULL;
        if (ncrls > 0)
            pcrls = NULL;
        failed = FAIL_NAME;
        if (failed != NULL && !quiet)
            BIO_printf(bio_err, "Could not find or decode");
    }

    if (failed != NULL && !quiet) {
        unsigned long err = ERR_peek_last_error();

        /* continue the error message with the type of credential affected */
        if (desc != NULL && strstr(desc, failed) != NULL) {
            BIO_printf(bio_err, " %s", desc);
        } else {
            BIO_printf(bio_err, " %s", failed);
            if (desc != NULL)
                BIO_printf(bio_err, " of %s", desc);
        }
        if (uri != NULL)
            BIO_printf(bio_err, " from %s", uri);
        if (ERR_SYSTEM_ERROR(err)) {
            /* provide more readable diagnostic output */
            BIO_printf(bio_err, ": %s", strerror(ERR_GET_REASON(err)));
            ERR_pop_to_mark();
            ERR_set_mark();
        }
        BIO_printf(bio_err, "\n");
        ERR_print_errors(bio_err);
    }
    if (quiet || failed == NULL)
        /* clear any suppressed or spurious errors */
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();
    return failed == NULL;
}

EVP_PKEY *FILES_load_key_ex(OSSL_LIB_CTX *libctx, const char *propq,
                            const char *uri, int format, bool maybe_stdin,
                            const char *source, const char *desc)
{
    char *pass;
    EVP_PKEY *pkey = NULL;

    if (desc == NULL)
        desc = "private key";
    pass = FILES_get_pass(source, desc);
    (void)load_key_certs_crls(libctx, propq, uri, format, maybe_stdin, pass, desc, false,
                              &pkey, NULL, NULL, NULL, NULL, NULL, NULL);
    UTIL_cleanse_free(pass);
    return pkey;
}

EVP_PKEY *FILES_load_pubkey_ex(OSSL_LIB_CTX *libctx, const char *propq,
                               const char *uri, int format, bool maybe_stdin,
                               const char *source, const char *desc)
{
    char *pass = FILES_get_pass(source, desc);
    EVP_PKEY *pkey = NULL;

    if (desc == NULL)
        desc = "public key";
    (void)load_key_certs_crls(libctx, propq, uri, format, maybe_stdin, pass, desc, false,
                              NULL, &pkey, NULL, NULL, NULL, NULL, NULL);
    UTIL_cleanse_free(pass);
    return pkey;
}

X509 *FILES_load_cert_ex(OSSL_LIB_CTX *libctx, const char *propq,
                         const char *uri, int format, bool maybe_stdin,
                         OPTIONAL const char *source, OPTIONAL const char *desc,
                         int type_CA, OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    char *pass;
    X509 *cert;

    if (desc == NULL)
        desc = "certificate";
    pass = FILES_get_pass(source, desc);
    (void)load_key_certs_crls(libctx, propq, uri, format, maybe_stdin, pass, desc, false,
                              NULL, NULL, NULL, &cert, NULL, NULL, NULL);
    UTIL_cleanse_free(pass);
    if (!CERT_check(uri, cert, type_CA, vpm) && vpm != NULL) {
        X509_free(cert);
        cert = NULL;
    }
    return cert;
}

bool FILES_load_certs_ex(OSSL_LIB_CTX *libctx, const char *propq,
                         const char *uri, int format, bool maybe_stdin,
                         const char *source, const char *desc,
                         int type_CA, OPTIONAL X509_VERIFY_PARAM *vpm,
                         OPTIONAL X509 **cert, OPTIONAL STACK_OF(X509) **certs)
{
    char *pass = FILES_get_pass(source, desc);
    bool res;

    if (desc == NULL)
        desc = "CRLs";
    res = load_key_certs_crls(libctx, propq, uri,
                              format, maybe_stdin, pass, desc, false,
                              NULL, NULL, NULL, cert, certs, NULL, NULL);
    UTIL_cleanse_free(pass);

    if (!res)
        goto end;
    if (cert != NULL && !CERT_check(uri, *cert, certs == NULL ?
                                    type_CA : 0 /* tentatively warn on CA cert */, vpm)
        && certs == NULL /* be strict if only cert loaded */)
        res = false;
    if (certs != NULL && !CERT_check_all(uri, *certs,
                                         cert == NULL ? type_CA : 1 /* warn on non-CA certs */, vpm)
        && cert == NULL /* be strict if only cert list loaded */)
        res = false;

 end:
    if (!res) {
        if (cert != NULL) {
            X509_free(*cert);
            *cert = NULL;
        }
        if (certs != NULL) {
            CERTS_free(*certs);
            *certs = NULL;
        }
    }
    return res;
}

STACK_OF(X509) *load_certs_pwd(const char *files, const char *source,
                               const char *desc, int type_CA,
                               OPTIONAL X509_VERIFY_PARAM *vpm)
{
    STACK_OF(X509) *certs = NULL;

    (void)FILES_load_certs_ex(app_get0_libctx(), app_get0_propq(), files, FORMAT_UNDEF,
                              false, source, desc, type_CA, vpm, NULL, &certs);
    return certs;
}

X509_CRL *FILES_load_crl_ex(OSSL_LIB_CTX *libctx, const char *propq, const char *uri,
                            int format, int maybe_stdin, int timeout, OPTIONAL const char *desc)
{
    X509_CRL *crl = NULL;

    if (desc == NULL)
        desc = "CRL";
    if (CONN_IS_HTTPS(uri)) {
        BIO_printf(bio_err, "Loading %s over HTTPS is unsupported\n", desc);
    } else if (CONN_IS_HTTP(uri)) {
        crl = X509_CRL_load_http(uri, NULL, NULL, timeout);
        if (crl == NULL) {
            ERR_print_errors(bio_err);
            BIO_printf(bio_err, "Unable to load %s from %s\n", desc, uri);
        }
    } else {
        (void)load_key_certs_crls(libctx, propq,
                                  uri, format, maybe_stdin, NULL, desc, false,
                                  NULL, NULL,  NULL, NULL, NULL, &crl, NULL);
    }
    return crl;
}

STACK_OF(X509_CRL) *FILES_load_crls_ex(OSSL_LIB_CTX *libctx, const char *propq,
                                       const char *files, int format, int timeout,
                                       OPTIONAL const char *desc)
{
    bool res = false;
    STACK_OF(X509_CRL) *crls = NULL;

    if (desc == NULL)
        desc = "CRLs";
    if (strchr(files, ',') != NULL || strchr(files, ' ') != NULL ||
        strchr(files, '\t') != NULL || strchr(files, '\n') != NULL)
        return FILES_load_crls_multi(files, format, timeout, desc);

    const char *uri = files;
    if (CONN_IS_HTTPS(uri)) {
        BIO_printf(bio_err, "Loading %s over HTTPS is unsupported\n", desc);
    } else if (CONN_IS_HTTP(uri)) {
        crls = FILES_load_crls_multi(uri, format, timeout, desc);
        res = crls != NULL;
        if (crls == NULL) {
            ERR_print_errors(bio_err);
            BIO_printf(bio_err, "Unable to download %s from %s\n", desc, uri);
        }
    } else {
        res = load_key_certs_crls(libctx, propq, uri, format, false, NULL, desc, false,
                                  NULL, NULL, NULL, NULL, NULL, NULL, &crls);
    }
    if (!res) {
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        crls = NULL;
    }

    return crls;
}

/*
 * extend or create cert store structure with cert(s) read from file
 */
static
bool STORE_load_more_check_ex(OSSL_LIB_CTX *libctx, const char *propq,
                              X509_STORE **pstore, const char *file,
                              file_format_t format, OPTIONAL const char *desc,
                              OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx)
{
    if (pstore is_eq 0 or file is_eq 0) {
        LOG_err("null pointer argument");
        goto err;
    }

#ifdef DEBUG
    LOG(FL_DEBUG, "Loading %s from file '%s'", desc not_eq 0 ? desc : "?", file);
#endif
    const char *store_desc = desc;
    if (store_desc != NULL) {
        CHECK_AND_SKIP_PREFIX(store_desc, "trusted certs for ");
        CHECK_AND_SKIP_PREFIX(store_desc, "trusted certificates for ");
    }

    if (ctx == NULL
#ifdef SECUTILS_USE_ICV
        or FILES_check_icv(ctx, file)
#endif
        ) {
        STACK_OF(X509) *certs = NULL;
        bool res = FILES_load_certs_ex(libctx, propq, file, format,
                                       false /* maybe_stdin */, NULL /* source */, desc,
                                       vpm != NULL ? 1 /* strictly check CA */ : -1,
                                       vpm, NULL, &certs);

        if (res && sk_X509_num(certs) == 0) {
            if (certs != 0)
                LOG(FL_ERR, "No %s in %s", desc not_eq 0 ? desc : "certs", file);
            CERTS_free(certs);
            goto err;
        }

        if (vpm == NULL)
            (void)CERT_check_all(file, certs, 1 /* warn on non-CA certs */, NULL);
        *pstore = STORE_create(*pstore, 0, certs);
        CERTS_free(certs);
        return *pstore not_eq 0 && STORE_set1_desc(*pstore, store_desc);
    }

err:
    LOG(FL_ERR, "Could not load %s", desc not_eq 0 ? desc : file);
    return false;
}

X509_STORE *STORE_load_check_ex(OSSL_LIB_CTX *libctx, const char *propq,
                                const char *files, OPTIONAL const char *desc,
                                OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx)

{
    X509_STORE *store = 0;

    if (files is_eq 0) {
        LOG_err("null pointer files arg");
        return 0;
    }

    char *names = OPENSSL_strdup(files);
    if (names is_eq 0) {
        LOG_err("Out of memory");
        return 0;
    }

    char *file;
    char *next;
    for (file = names; file not_eq 0; file = next) {
        next = UTIL_next_item(file); /* must do this here to split string */
        if (not STORE_load_more_check_ex(libctx, propq, &store, file, FORMAT_PEM, desc, vpm, ctx)) {
            X509_STORE_free(store);
            store = 0;
            break;
        }
    }

    OPENSSL_free(names);
    return store;
}

static
bool FILES_load_credentials_ex(OPTIONAL OSSL_LIB_CTX *libctx, const char *propq,
                               OPTIONAL const char *certs, OPTIONAL OPTIONAL const char *key,
                               file_format_t file_format, bool maybe_stdin,
                               OPTIONAL const char *source, OPTIONAL const char *desc,
                               OPTIONAL X509_VERIFY_PARAM *vpm, int type_CA,
                               OPTIONAL EVP_PKEY **pkey, OPTIONAL X509 **cert,
                               OPTIONAL STACK_OF(X509) **chain)
{
    bool joint_credentials = certs != NULL && key != NULL && strcmp(certs, key) == 0;
    bool res = false;

    if (joint_credentials) {
        char *pass = FILES_get_pass(source, desc);

        if (desc == NULL)
            desc = "both private key and related certificate(s)";
        res = load_key_certs_crls(libctx, propq, certs /* == key */,
                                  file_format, maybe_stdin, pass, desc, false,
                                  pkey, NULL, NULL, cert, chain, NULL, NULL);
        UTIL_cleanse_free(pass);
        if (cert != NULL)
            (void)CERT_check(certs, *cert, 0 /* tentatively warn on CA cert */, vpm);
        if (chain != NULL)
            (void)CERT_check_all(certs, *chain, 1 /* warn on non-CA certs */, vpm);
    }
    if (!res) {
        if (key != NULL && pkey != NULL
            && (*pkey = FILES_load_key_ex(libctx, propq, key, file_format, maybe_stdin,
                                          source, desc == NULL ? "private key" : desc)) == NULL)
            goto err;
        if (certs != NULL && (cert != NULL || chain != NULL)
            && !FILES_load_certs_ex(libctx, propq, certs, file_format, maybe_stdin,
                                    source, desc == NULL ? "certificate(s)" : desc,
                                    type_CA, vpm, cert, chain))
            goto err;
    }
    return true;

err:
    if (desc == NULL)
        desc = pkey == NULL ? "certificate(s)" : certs == NULL ? "private key" :
            "private key and related certificate(s)";
    LOG(FL_ERR, "Could not load %s from %s%s%s", desc,
        key, pkey == NULL || certs == NULL || joint_credentials ? "" : " and ",
        joint_credentials ? "" : certs);
    return false;
}

CREDENTIALS *CREDENTIALS_load_ex(OPTIONAL OSSL_LIB_CTX *libctx, const char *propq,
                                 OPTIONAL const char *certs, OPTIONAL const char *key,
                                 OPTIONAL const char *source,
                                 OPTIONAL const char *desc,
                                 OPTIONAL X509_VERIFY_PARAM *vpm)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    CREDENTIALS *res;

    if (!FILES_load_credentials_ex(libctx, propq, certs, key, FORMAT_PEM, false,
                                   source, desc, vpm, -1, &pkey, &cert, &chain))
        return NULL;

    res = CREDENTIALS_new(pkey, cert, chain, NULL, NULL);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    CERTS_free(chain);
    return res;
}
