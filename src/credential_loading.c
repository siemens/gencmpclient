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
#include <secutils/credentials/credentials.h>
#include <secutils/credentials/store.h>

#include "credential_loading.h"

/* from OpenSSL/apps/lib/app_libctx.c: */
static OSSL_LIB_CTX *app_libctx = NULL;
static const char *app_propq = NULL;

int app_set_propq(const char *arg)
{
    app_propq = arg;
    return 1;
}

const char *app_get0_propq(void)
{
    return app_propq;
}

OSSL_LIB_CTX *app_get0_libctx(void)
{
    return app_libctx;
}

OSSL_LIB_CTX *app_create_libctx(void)
{
    /*
     * Load the NULL provider into the default library context and create a
     * library context which will then be used for any OPT_PROV options.
     */
    if (app_libctx == NULL) {
        if (!app_provider_load(NULL, "null")) {
            LOG(FL_ERR, "Failed to create null provider");
            return NULL;
        }
        app_libctx = OSSL_LIB_CTX_new();
    }
    if (app_libctx == NULL)
        LOG(FL_ERR, "Failed to create library context");
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

int app_provider_load(OPTIONAL OSSL_LIB_CTX *libctx, const char *provider_name)
{
    OSSL_PROVIDER *prov;

    prov = OSSL_PROVIDER_load(libctx, provider_name);
    if (prov == NULL) {
        LOG(FL_ERR, "unable to load provider %s\n"
            "Hint: use -provider-path option or OPENSSL_MODULES environment variable.",
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

STACK_OF(X509) *load_certs_multifile(const char *files, OPTIONAL const char *source,
                                     OPTIONAL const char *desc, int type_CA,
                                     OPTIONAL X509_VERIFY_PARAM *vpm)
{
    STACK_OF(X509) *certs = NULL;

    (void)CREDS_load_certs_ex(app_get0_libctx(), app_get0_propq(), files, FORMAT_UNDEF,
                              0 /* timeout */, source, desc,
                              1 /* min_num */, type_CA, vpm, NULL, &certs);
    return certs;
}
