#include <string.h>

#include "osslsigncode.h"

void init_ms_authcode(MS_AUTHCODE *ptr) {
    /* Set up OpenSSL */
    ERR_load_crypto_strings();
    OPENSSL_add_all_algorithms_conf();


    memset(ptr, 0, sizeof(MS_AUTHCODE));
    ptr->mdtype = -1;
    ptr->phtype = -1;
    ptr->ignore_expired = TRUE;
    ptr->verify_flags = 0; //PKCS7_NOVERIFY;
    ptr->store = X509_STORE_new();

    // Make some more room for an extra pointer which can get 
    // passed around to callbacks if required.
    ptr->store = OPENSSL_realloc(ptr->store, sizeof(X509_STORE_MS_EXTRA));
}

void cleanup_ms_authcode(MS_AUTHCODE *ptr) {
    if (ptr->ph != NULL) {
        free(ptr->ph);
    }

    if (ptr->signers != NULL) {
        sk_X509_free(ptr->signers);
    }

    if (ptr->p7 != NULL) {
        PKCS7_free(ptr->p7);
    }

    if (ptr->store != NULL) {
        OPENSSL_free(ptr->store);
    }
}

struct verify_error_st {
    int err;
    char *err_name;
} verify_error_defs[] = {
#define VERRNAME(x) { x, #x }
    VERRNAME(X509_V_OK),
    VERRNAME(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT),
    VERRNAME(X509_V_ERR_UNABLE_TO_GET_CRL),
    VERRNAME(X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE),
    VERRNAME(X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE),
    VERRNAME(X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY),
    VERRNAME(X509_V_ERR_CERT_SIGNATURE_FAILURE),
    VERRNAME(X509_V_ERR_CRL_SIGNATURE_FAILURE),
    VERRNAME(X509_V_ERR_CERT_NOT_YET_VALID),
    VERRNAME(X509_V_ERR_CERT_HAS_EXPIRED),
    VERRNAME(X509_V_ERR_CRL_NOT_YET_VALID),
    VERRNAME(X509_V_ERR_CRL_HAS_EXPIRED),
    VERRNAME(X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD),
    VERRNAME(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD),
    VERRNAME(X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD),
    VERRNAME(X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD),
    VERRNAME(X509_V_ERR_OUT_OF_MEM),
    VERRNAME(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT),
    VERRNAME(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN),
    VERRNAME(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
    VERRNAME(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE),
    VERRNAME(X509_V_ERR_CERT_CHAIN_TOO_LONG),
    VERRNAME(X509_V_ERR_CERT_REVOKED),
    VERRNAME(X509_V_ERR_INVALID_CA),
    VERRNAME(X509_V_ERR_PATH_LENGTH_EXCEEDED),
    VERRNAME(X509_V_ERR_INVALID_PURPOSE),
    VERRNAME(X509_V_ERR_CERT_UNTRUSTED),
    VERRNAME(X509_V_ERR_CERT_REJECTED),
    VERRNAME(X509_V_ERR_SUBJECT_ISSUER_MISMATCH),
    VERRNAME(X509_V_ERR_AKID_SKID_MISMATCH),
    VERRNAME(X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH),
    VERRNAME(X509_V_ERR_KEYUSAGE_NO_CERTSIGN),
    VERRNAME(X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER),
    VERRNAME(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION),
    VERRNAME(X509_V_ERR_KEYUSAGE_NO_CRL_SIGN),
    VERRNAME(X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION),
    VERRNAME(X509_V_ERR_INVALID_NON_CA),
    VERRNAME(X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED),
    VERRNAME(X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE),
    VERRNAME(X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED),
    VERRNAME(X509_V_ERR_INVALID_EXTENSION),
    VERRNAME(X509_V_ERR_INVALID_POLICY_EXTENSION),
    VERRNAME(X509_V_ERR_NO_EXPLICIT_POLICY),
    VERRNAME(X509_V_ERR_DIFFERENT_CRL_SCOPE),
    VERRNAME(X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE),
    VERRNAME(X509_V_ERR_UNNESTED_RESOURCE),
    VERRNAME(X509_V_ERR_PERMITTED_VIOLATION),
    VERRNAME(X509_V_ERR_EXCLUDED_VIOLATION),
    VERRNAME(X509_V_ERR_SUBTREE_MINMAX),
    VERRNAME(X509_V_ERR_APPLICATION_VERIFICATION),
    VERRNAME(X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE),
    VERRNAME(X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX),
    VERRNAME(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX),
    VERRNAME(X509_V_ERR_CRL_PATH_VALIDATION_ERROR),
    { 0, NULL }
};

char *verr_code_to_name(int err) {
    struct verify_error_st *ptr = verify_error_defs;

    while (ptr->err_name != NULL) {
        if (ptr->err == err) {
            return ptr->err_name;
        }
        ptr++;
    }
    return "ILLEGAL ERROR";
}

/*
 * Just being lazy, this way I can pass temporary strings to openssl.
 */

void X509_set_extra_params(MS_AUTHCODE *ptr, int purpose, char *CAfile, char *CApath) {
    X509_STORE_set_purpose(ptr->store, purpose);
    X509_STORE_load_locations(ptr->store, CAfile, CApath);
}

int is_loaded(MS_AUTHCODE *ptr) {
    return ptr->p7 != NULL;
}