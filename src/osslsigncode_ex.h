#ifndef __OSSLSIGNCODE_EX_H__
#define __OSSLSIGNCODE_EX_H__

#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

// Tacking a little bit of extra data to the X509_STORE
// to access from callbacks when building a list for example.
// Not sure if this is safe.
typedef struct {
    X509_STORE store;
    void *data;
} X509_STORE_MS_EXTRA;

typedef struct ms_authcode {
    // State.
    PKCS7 *p7;
    unsigned char mdbuf[EVP_MAX_MD_SIZE]; // Message Digest Buffer
    unsigned char *ph; // Page Hash pointer
    int mdtype; // Message Digest Type
    int phtype; // Page Hash Type
    STACK_OF(X509) *signers;
    int num_signers;
    STACK_OF(X509) *certs;
    int num_certs;
    X509_STORE *store;

    // Delayed parameters which are used during verification.
    int verify_flags;
    int ignore_expired;

    // TODO: Crl's.
} MS_AUTHCODE;


// Simple callback system to return strings to calling code.
// Mainly designed for use with python to spare me managing memory
// myself and passing around structured data.
typedef struct ms_authcode_callback {
    void (*callback)(struct ms_authcode_callback *, char *, char *);
    void *data;
    MS_AUTHCODE *ms_auth;
} MS_AUTHCODE_CALLBACK;


extern void init_ms_authcode(MS_AUTHCODE *ptr);
extern void cleanup_ms_authcode(MS_AUTHCODE *ptr);
extern int is_loaded(MS_AUTHCODE *);
extern void X509_set_extra_params(MS_AUTHCODE *, int , char *, char *);

extern char *verr_code_to_name(int err);
#endif