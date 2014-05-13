/*  ---------------------------------------------------------
    Everything below has been taken from osslsigncode.c,v 1.6
    http://sourceforge.net/projects/osslsigncode/
    by Per Allansson <pallansson@gmail.com>
    --------------------------------------------------------- */

#ifndef __OSSLSIGNCODE_H__
#define __OSSLSIGNCODE_H__

#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>

#include "osslsigncode_ex.h"

/* MS Authenticode object ids */
#define SPC_INDIRECT_DATA_OBJID  "1.3.6.1.4.1.311.2.1.4"
#define SPC_STATEMENT_TYPE_OBJID "1.3.6.1.4.1.311.2.1.11"
#define SPC_SP_OPUS_INFO_OBJID   "1.3.6.1.4.1.311.2.1.12"
#define SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID "1.3.6.1.4.1.311.2.1.21"
#define SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID "1.3.6.1.4.1.311.2.1.22"
#define SPC_MS_JAVA_SOMETHING    "1.3.6.1.4.1.311.15.1"
#define SPC_PE_IMAGE_DATA_OBJID  "1.3.6.1.4.1.311.2.1.15"
#define SPC_CAB_DATA_OBJID       "1.3.6.1.4.1.311.2.1.25"
#define SPC_TIME_STAMP_REQUEST_OBJID "1.3.6.1.4.1.311.3.2.1"
#define SPC_SIPINFO_OBJID        "1.3.6.1.4.1.311.2.1.30"

#define SPC_PE_IMAGE_PAGE_HASHES_V1 "1.3.6.1.4.1.311.2.3.1" /* Page hash using SHA1 */
#define SPC_PE_IMAGE_PAGE_HASHES_V2 "1.3.6.1.4.1.311.2.3.2" /* Page hash using SHA256 */

#define SPC_RFC3161_OBJID "1.3.6.1.4.1.311.3.3.1"

/* Supported extensions 
    http://msdn.microsoft.com/en-us/library/windows/desktop/aa379367(v=vs.85).aspx
 */
#define XCN_OID_AUTHORITY_INFO_ACCESS "1.3.6.1.5.5.7.1.1"
#define XCN_OID_CRL_DIST_POINTS "2.5.29.31"

/* 1.3.6.1.4.1.311.4... MS Crypto 2.0 stuff... */

#define WIN_CERT_REVISION_2             0x0200
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA  0x0002

#define GET_UINT16_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8))

#define GET_UINT32_LE(p) (((u_char*)(p))[0] | (((u_char*)(p))[1]<<8) |  \
                          (((u_char*)(p))[2]<<16) | (((u_char*)(p))[3]<<24))

#define PUT_UINT16_LE(i,p)                      \
    ((u_char*)(p))[0] = (i) & 0xff;             \
    ((u_char*)(p))[1] = ((i)>>8) & 0xff

#define PUT_UINT32_LE(i,p)                      \
    ((u_char*)(p))[0] = (i) & 0xff;             \
    ((u_char*)(p))[1] = ((i)>>8) & 0xff;        \
    ((u_char*)(p))[2] = ((i)>>16) & 0xff;       \
    ((u_char*)(p))[3] = ((i)>>24) & 0xff

extern int load_pkcs7_der(MS_AUTHCODE *, unsigned char *, int );
extern int verify_p7(MS_AUTHCODE *, MS_AUTHCODE_CALLBACK *);
extern void get_certificate(MS_AUTHCODE *, int, int, MS_AUTHCODE_CALLBACK *);


#endif