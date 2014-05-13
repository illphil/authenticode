cdef extern from "osslsigncode_ex.h":
    struct ms_authcode:
        char *mdbuf
        int mdtype
        int phtype
        int verify_flags
        int ignore_expired
        int num_signers
        int num_certs

    struct ms_authcode_callback:
        void (*callback)(ms_authcode_callback *, char *, char *)
        void *data

    void init_ms_authcode(ms_authcode *)
    void cleanup_ms_authcode(ms_authcode *)
    int verify_p7(ms_authcode *, ms_authcode_callback *)
    void X509_set_extra_params(ms_authcode *, int , char *, char *)
    void get_certificate(ms_authcode *, int , int , ms_authcode_callback *)
    int is_loaded(ms_authcode *)

cdef extern from "osslsigncode.h":
    int load_pkcs7_der(ms_authcode *, unsigned char *, int)

cdef extern from "openssl/evp.h":
    struct env_md_st:
        pass
    env_md_st *EVP_get_digestbyname(char *)
    int EVP_MD_size(env_md_st *md)

cdef extern from "openssl/asn1.h":
    struct asn1_object_st:
        pass

cdef extern from "openssl/objects.h":
    int OBJ_obj2nid(asn1_object_st *o)
    char *OBJ_nid2sn(int)

cdef extern from "Python.h":
    object PyString_FromString(char *s)
    object PyString_FromStringAndSize(char *s, Py_ssize_t len)