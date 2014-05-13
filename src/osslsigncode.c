#include <stdio.h>
#include <string.h>

#include "osslsigncode.h"

/*
  ASN.1 definitions (more or less from official MS Authenticode docs)
*/

typedef struct {
    int type;
    union {
        ASN1_BMPSTRING *unicode;
        ASN1_IA5STRING *ascii;
    } value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString)

ASN1_CHOICE(SpcString) = {
    ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING , 0),
    ASN1_IMP_OPT(SpcString, value.ascii,   ASN1_IA5STRING,  1)
} ASN1_CHOICE_END(SpcString)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)


typedef struct {
    ASN1_OCTET_STRING *classId;
    ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)

ASN1_SEQUENCE(SpcSerializedObject) = {
    ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)


typedef struct {
    int type;
    union {
        ASN1_IA5STRING *url;
        SpcSerializedObject *moniker;
        SpcString *file;
    } value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink)

ASN1_CHOICE(SpcLink) = {
    ASN1_IMP_OPT(SpcLink, value.url,     ASN1_IA5STRING,      0),
    ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
    ASN1_EXP_OPT(SpcLink, value.file,    SpcString,           2)
} ASN1_CHOICE_END(SpcLink)

IMPLEMENT_ASN1_FUNCTIONS(SpcLink)


typedef struct {
    SpcString *programName;
    SpcLink   *moreInfo;
} SpcSpOpusInfo;

DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)

ASN1_SEQUENCE(SpcSpOpusInfo) = {
    ASN1_EXP_OPT(SpcSpOpusInfo, programName, SpcString, 0),
    ASN1_EXP_OPT(SpcSpOpusInfo, moreInfo, SpcLink, 1)
} ASN1_SEQUENCE_END(SpcSpOpusInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSpOpusInfo)

typedef struct {
    ASN1_OBJECT *type;
    ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
    ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
    ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

typedef struct {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
    ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
    ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)


typedef struct {
    AlgorithmIdentifier *digestAlgorithm;
    ASN1_OCTET_STRING *digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo)

ASN1_SEQUENCE(DigestInfo) = {
    ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
    ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo)

IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)


typedef struct {
    SpcAttributeTypeAndOptionalValue *data;
    DigestInfo *messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)

ASN1_SEQUENCE(SpcIndirectDataContent) = {
    ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
    ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent)

IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)


typedef struct {
    ASN1_BIT_STRING* flags;
    SpcLink *file;
} SpcPeImageData;

DECLARE_ASN1_FUNCTIONS(SpcPeImageData)

ASN1_SEQUENCE(SpcPeImageData) = {
    ASN1_SIMPLE(SpcPeImageData, flags, ASN1_BIT_STRING),
    ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData)


typedef struct {
    ASN1_INTEGER *a;
    ASN1_OCTET_STRING *string;
    ASN1_INTEGER *b;
    ASN1_INTEGER *c;
    ASN1_INTEGER *d;
    ASN1_INTEGER *e;
    ASN1_INTEGER *f;
} SpcSipInfo;

DECLARE_ASN1_FUNCTIONS(SpcSipInfo)

ASN1_SEQUENCE(SpcSipInfo) = {
    ASN1_SIMPLE(SpcSipInfo, a, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, string, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SpcSipInfo, b, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, c, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, d, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, e, ASN1_INTEGER),
    ASN1_SIMPLE(SpcSipInfo, f, ASN1_INTEGER),
} ASN1_SEQUENCE_END(SpcSipInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSipInfo)


#ifdef ENABLE_CURL

typedef struct {
    ASN1_OBJECT *type;
    ASN1_OCTET_STRING *signature;
} TimeStampRequestBlob;

DECLARE_ASN1_FUNCTIONS(TimeStampRequestBlob)

ASN1_SEQUENCE(TimeStampRequestBlob) = {
    ASN1_SIMPLE(TimeStampRequestBlob, type, ASN1_OBJECT),
    ASN1_EXP_OPT(TimeStampRequestBlob, signature, ASN1_OCTET_STRING, 0)
} ASN1_SEQUENCE_END(TimeStampRequestBlob)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequestBlob)



typedef struct {
    ASN1_OBJECT *type;
    TimeStampRequestBlob *blob;
} TimeStampRequest;

DECLARE_ASN1_FUNCTIONS(TimeStampRequest)

ASN1_SEQUENCE(TimeStampRequest) = {
    ASN1_SIMPLE(TimeStampRequest, type, ASN1_OBJECT),
    ASN1_SIMPLE(TimeStampRequest, blob, TimeStampRequestBlob)
} ASN1_SEQUENCE_END(TimeStampRequest)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampRequest)


/* RFC3161 Time stamping */

typedef struct {
    ASN1_INTEGER *status;
    STACK_OF(ASN1_UTF8STRING) *statusString;
    ASN1_BIT_STRING *failInfo;
} PKIStatusInfo;

DECLARE_ASN1_FUNCTIONS(PKIStatusInfo)

ASN1_SEQUENCE(PKIStatusInfo) = {
    ASN1_SIMPLE(PKIStatusInfo, status, ASN1_INTEGER),
    ASN1_SEQUENCE_OF_OPT(PKIStatusInfo, statusString, ASN1_UTF8STRING),
    ASN1_OPT(PKIStatusInfo, failInfo, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(PKIStatusInfo)

IMPLEMENT_ASN1_FUNCTIONS(PKIStatusInfo)


typedef struct {
    PKIStatusInfo *status;
    PKCS7 *token;
} TimeStampResp;

DECLARE_ASN1_FUNCTIONS(TimeStampResp)

ASN1_SEQUENCE(TimeStampResp) = {
    ASN1_SIMPLE(TimeStampResp, status, PKIStatusInfo),
    ASN1_OPT(TimeStampResp, token, PKCS7)
} ASN1_SEQUENCE_END(TimeStampResp)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampResp)

typedef struct {
    AlgorithmIdentifier *digestAlgorithm;
    ASN1_OCTET_STRING *digest;
} MessageImprint;

DECLARE_ASN1_FUNCTIONS(MessageImprint)

ASN1_SEQUENCE(MessageImprint) = {
    ASN1_SIMPLE(MessageImprint, digestAlgorithm, AlgorithmIdentifier),
    ASN1_SIMPLE(MessageImprint, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(MessageImprint)

IMPLEMENT_ASN1_FUNCTIONS(MessageImprint)

typedef struct {
    ASN1_INTEGER *version;
    MessageImprint *messageImprint;
    ASN1_OBJECT *reqPolicy;
    ASN1_INTEGER *nonce;
    ASN1_BOOLEAN *certReq;
    STACK_OF(X509_EXTENSION) *extensions;
} TimeStampReq;

DECLARE_ASN1_FUNCTIONS(TimeStampReq)

ASN1_SEQUENCE(TimeStampReq) = {
    ASN1_SIMPLE(TimeStampReq, version, ASN1_INTEGER),
    ASN1_SIMPLE(TimeStampReq, messageImprint, MessageImprint),
    ASN1_OPT   (TimeStampReq, reqPolicy, ASN1_OBJECT),
    ASN1_OPT   (TimeStampReq, nonce, ASN1_INTEGER),
    ASN1_SIMPLE(TimeStampReq, certReq, ASN1_BOOLEAN),
    ASN1_IMP_SEQUENCE_OF_OPT(TimeStampReq, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(TimeStampReq)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampReq)

#endif /* ENABLE_CURL */

unsigned char classid_page_hash[] = {
    0xA6, 0xB5, 0x86, 0xD5, 0xB4, 0xA1, 0x24, 0x66,
    0xAE, 0x05, 0xA2, 0x17, 0xDA, 0x8E, 0x60, 0xD6
};

unsigned int asn1_simple_hdr_len(const unsigned char *p, unsigned int len) {
    if (len <= 2 || p[0] > 0x31)
        return 0;
    return (p[1]&0x80) ? (2 + (p[1]&0x7f)) : 2;
}

static void extract_page_hash (SpcAttributeTypeAndOptionalValue *obj,
                               unsigned char **ph, unsigned int *phlen, int *phtype)
{
    *phlen = 0;

    const unsigned char *blob = obj->value->value.sequence->data;
    SpcPeImageData *id = d2i_SpcPeImageData(NULL, &blob, obj->value->value.sequence->length);
    if (id == NULL)
        return;

    if (id->file->type != 1) {
        SpcPeImageData_free(id);
        return;
    }

    SpcSerializedObject *so = id->file->value.moniker;
    if (so->classId->length != sizeof(classid_page_hash) ||
        memcmp(so->classId->data, classid_page_hash, sizeof (classid_page_hash))) {
        SpcPeImageData_free(id);
        return;
    }

    /* skip ASN.1 SET hdr */
    unsigned int l = asn1_simple_hdr_len(so->serializedData->data, so->serializedData->length);
    blob = so->serializedData->data + l;
    obj = d2i_SpcAttributeTypeAndOptionalValue(NULL, &blob, so->serializedData->length - l);
    SpcPeImageData_free(id);
    if (!obj)
        return;

    char buf[128];
    *phtype = 0;
    buf[0] = 0x00;
    OBJ_obj2txt(buf, sizeof(buf), obj->type, 1);
    if (!strcmp(buf, SPC_PE_IMAGE_PAGE_HASHES_V1)) {
        *phtype = NID_sha1;
    } else if (!strcmp(buf, SPC_PE_IMAGE_PAGE_HASHES_V2)) {
        *phtype = NID_sha256;
    } else {
        SpcAttributeTypeAndOptionalValue_free(obj);
        return;
    }

    /* Skip ASN.1 SET hdr */
    unsigned int l2 = asn1_simple_hdr_len(obj->value->value.sequence->data, obj->value->value.sequence->length);
    /* Skip ASN.1 OCTET STRING hdr */
    l =  asn1_simple_hdr_len(obj->value->value.sequence->data + l2, obj->value->value.sequence->length - l2);
    l += l2;
    *phlen = obj->value->value.sequence->length - l;
    *ph = malloc(*phlen);
    memcpy(*ph, obj->value->value.sequence->data + l, *phlen);
    SpcAttributeTypeAndOptionalValue_free(obj);
}

// Page hash is the loaded image?

/*
unsigned char *calc_page_hash(char *indata, unsigned int peheader, int pe32plus,
                                     unsigned int sigpos, int phtype, unsigned int *rphlen)
{
    unsigned short nsections = GET_UINT16_LE(indata + peheader + 6);
    unsigned int pagesize = GET_UINT32_LE(indata + peheader + 56);
    unsigned int hdrsize = GET_UINT32_LE(indata + peheader + 84);
    const EVP_MD *md = EVP_get_digestbynid(phtype);
    int pphlen = 4 + EVP_MD_size(md);
    int phlen = pphlen * (3 + nsections + sigpos / pagesize);
    unsigned char *res = malloc(phlen);
    unsigned char *zeroes = calloc(pagesize, 1);
    EVP_MD_CTX mdctx;

    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit(&mdctx, md);
    EVP_DigestUpdate(&mdctx, indata, peheader + 88);
    EVP_DigestUpdate(&mdctx, indata + peheader + 92, 60 + pe32plus*16);
    EVP_DigestUpdate(&mdctx, indata + peheader + 160 + pe32plus*16, hdrsize - (peheader + 160 + pe32plus*16));
    EVP_DigestUpdate(&mdctx, zeroes, pagesize - hdrsize);
    memset(res, 0, 4);
    EVP_DigestFinal(&mdctx, res + 4, NULL);

    unsigned short sizeofopthdr = GET_UINT16_LE(indata + peheader + 20);
    char *sections = indata + peheader + 24 + sizeofopthdr;
    int i, pi = 1;
    unsigned int lastpos = 0;
    for (i=0; i<nsections; i++) {
        unsigned int rs = GET_UINT32_LE(sections + 16);
        unsigned int ro = GET_UINT32_LE(sections + 20);
        unsigned int l;
        for (l=0; l < rs; l+=pagesize, pi++) {
            PUT_UINT32_LE(ro + l, res + pi*pphlen);
            EVP_DigestInit(&mdctx, md);
            if (rs - l < pagesize) {
                EVP_DigestUpdate(&mdctx, indata + ro + l, rs - l);
                EVP_DigestUpdate(&mdctx, zeroes, pagesize - (rs - l));
            } else {
                EVP_DigestUpdate(&mdctx, indata + ro + l, pagesize);
            }
            EVP_DigestFinal(&mdctx, res + pi*pphlen + 4, NULL);
        }
        lastpos = ro + rs;
        sections += 40;
    }
    PUT_UINT32_LE(lastpos, res + pi*pphlen);
    memset(res + pi*pphlen + 4, 0, EVP_MD_size(md));
    pi++;
    free(zeroes);
    *rphlen = pi*pphlen;
    return res;
}
*/

int load_pkcs7_der(MS_AUTHCODE *msa, unsigned char *data, int length) {
    PKCS7 *p7;
    int mdtype = -1, phtype = -1;
    unsigned char *mdbuf = msa->mdbuf;
    unsigned int phlen = 0;
    unsigned char *ph = NULL;
    ASN1_OBJECT *indir_objid = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);

    p7 = d2i_PKCS7(NULL, (const unsigned char **)&data, length);
    if (p7 && PKCS7_type_is_signed(p7) &&
        !OBJ_cmp(p7->d.sign->contents->type, indir_objid) &&
        p7->d.sign->contents->d.other->type == V_ASN1_SEQUENCE) {

        ASN1_STRING *astr = p7->d.sign->contents->d.other->value.sequence;
        const unsigned char *p = astr->data;
        SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(NULL, &p, astr->length);
        if (idc) {
            extract_page_hash(idc->data, &ph, &phlen, &phtype);
            if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
                mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
                memcpy(mdbuf, idc->messageDigest->digest->data, idc->messageDigest->digest->length);
            }
            SpcIndirectDataContent_free(idc);
        }
    }
    ASN1_OBJECT_free(indir_objid);
    if (p7 && mdtype == -1) {
        PKCS7_free(p7);
        p7 = NULL;
        return FALSE;
    }
    msa->p7 = p7;
    msa->mdtype = mdtype;
    msa->phtype = phtype;
    msa->ph = ph;

    msa->signers = PKCS7_get0_signers(p7, NULL, 0);
    msa->num_signers = sk_X509_num(msa->signers);
    msa->certs = p7->d.sign->cert;
    msa->num_certs = sk_X509_num(msa->certs);

    return TRUE;
}


static int pe_verify_cb(int ok, X509_STORE_CTX *store) {
    char *subject;
    char *err_name;
    X509_STORE_MS_EXTRA *store_ex = (X509_STORE_MS_EXTRA *)store->ctx;
    MS_AUTHCODE_CALLBACK *cb = (MS_AUTHCODE_CALLBACK *)store_ex->data;
    MS_AUTHCODE *ms_auth = cb->ms_auth;

    if (!ok) {
        int err = X509_STORE_CTX_get_error(store);
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        if (err != 0 && err <= X509_V_ERR_CRL_PATH_VALIDATION_ERROR) {
            err_name = verr_code_to_name(err);
            if (ms_auth->ignore_expired && err == X509_V_ERR_CERT_HAS_EXPIRED) {
                ok = 1;
            }
            subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            if (cb != NULL) {
                cb->callback(cb, err_name, subject);
            }
            OPENSSL_free(subject);
        }
    }

    return ok;
}

int verify_p7(MS_AUTHCODE *msa, MS_AUTHCODE_CALLBACK *cb) {
    PKCS7 *p7 = msa->p7;
    BIO *bio;

    int seqhdrlen = asn1_simple_hdr_len(p7->d.sign->contents->d.other->value.sequence->data,
                                        p7->d.sign->contents->d.other->value.sequence->length);
    bio = BIO_new_mem_buf(p7->d.sign->contents->d.other->value.sequence->data + seqhdrlen,
                          p7->d.sign->contents->d.other->value.sequence->length - seqhdrlen);

    X509_STORE_MS_EXTRA *store_ex = (X509_STORE_MS_EXTRA *)msa->store;
    store_ex->data = cb;
    cb->ms_auth = msa; // To pass ignore_expired to callback.

    // Install callback to catch errors.
    X509_STORE_set_verify_cb(msa->store, pe_verify_cb);
    int verok = PKCS7_verify(p7, p7->d.sign->cert, msa->store, bio, NULL, msa->verify_flags);
    BIO_free(bio);

    return verok;
}

void get_x509v3_extensions(STACK_OF(X509_EXTENSION) *sk_ext, MS_AUTHCODE_CALLBACK *cb) {
    int j, k, l;
    char buf[128];                                                             
    for (j = 0; j< sk_X509_EXTENSION_num(sk_ext); j++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(sk_ext, j);
        int nid = OBJ_obj2nid(ext->object);
        OBJ_obj2txt(buf, 128, ext->object, 0);
        if (nid == NID_info_access) {
            AUTHORITY_INFO_ACCESS *sk_aia;
            sk_aia = (AUTHORITY_INFO_ACCESS *)X509V3_EXT_d2i(ext);
            for(k=0; k < sk_ACCESS_DESCRIPTION_num(sk_aia); k++) {
                ACCESS_DESCRIPTION *ad;
                ad  = sk_ACCESS_DESCRIPTION_value(sk_aia, k);
                if (ad->location->type != GEN_URI)
                    continue;

                cb->callback(cb, buf, (char *)ad->location->d.ia5->data);
            }
            sk_ACCESS_DESCRIPTION_free(sk_aia);
        } else if (nid == NID_crl_distribution_points) {                                    
            CRL_DIST_POINTS *sk_cdp;
            sk_cdp = (CRL_DIST_POINTS *)X509V3_EXT_d2i(ext);                                
            for(k=0; k< sk_DIST_POINT_num(sk_cdp); k++) {
                DIST_POINT *dp = sk_DIST_POINT_value(sk_cdp, k);
                GENERAL_NAMES *gn = dp->distpoint->name.fullname;

                for(l=0;l<sk_GENERAL_NAME_num(gn); l++) {
                    GENERAL_NAME *n = sk_GENERAL_NAME_value(gn, l);                                 
                    if (n->type != GEN_URI)
                        continue;
                    cb->callback(cb, buf, (char *)n->d.ia5->data);
                }
            }
            sk_DIST_POINT_free(sk_cdp);
        }
    }
}

void get_certificate(MS_AUTHCODE *msa, int which, int index, MS_AUTHCODE_CALLBACK *cb) {
    X509 *cert;
    char *name;
    char hash[9];

    cert = sk_X509_value(which ? msa->signers : msa->certs, index);

    name = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    cb->callback(cb, "subject", name);
    OPENSSL_free(name);
    name = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    cb->callback(cb, "issuer", name);
    OPENSSL_free(name);

    snprintf(hash, 9, "%08x", (unsigned int)X509_subject_name_hash(cert));
    cb->callback(cb, "subject_name_hash", hash);
    snprintf(hash, 9, "%08x", (unsigned int)X509_issuer_name_hash(cert));
    cb->callback(cb, "issuer_name_hash", hash);

    get_x509v3_extensions(cert->cert_info->extensions, cb);
}
