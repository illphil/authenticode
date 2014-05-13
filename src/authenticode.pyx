"""This module can be used to verify Microsoft PE files.

It is based on code from osslsigncode.c,v 1.6
http://sourceforge.net/projects/osslsigncode/
by Per Allansson <pallansson@gmail.com>
"""

include "authenticode.pxi"

cdef void verify_callback(ms_authcode_callback *cb, char *err_name, char *subject):
    error = {
        "error": PyString_FromString(err_name),
        "subject": PyString_FromString(subject)
    }
    L = <object><void *>cb.data
    L.append(error)

cdef void certificate_callback(ms_authcode_callback *cb, char *key, char *value):
    if cb == NULL:
        return
    pydict = <object><void *>cb.data
    pykey = PyString_FromString(key)
    pyvalue = PyString_FromString(value)

    if pykey in ['issuer','subject','subject_name_hash','issuer_name_hash']:
        pydict[pykey] = pyvalue
        return

    if pykey not in pydict:
        pydict[pykey] = [pyvalue]
    else:
        pydict[pykey].append(pyvalue)

cdef class PEAuthenticode(object):
    cdef ms_authcode ms_auth

    def __init__(self, **kwargs):
        """Initialise PEAuthenticode class

        Keyword arguments:
        ignore_expired -- ignore expired certificates during verification
        verify_flags -- flags passed to PKCS7_verify() (default 0)
        purpose -- X509 certificate purpose (default 7 - X509_PURPOSE_ANY)
        CAfile -- cerficiate file like -CAfile flag in command line tool
        CApath -- cerficiate file like -CApath flag in command line tool
        sig -- DER format PKCS#7 signature as a string
        """
        init_ms_authcode(&self.ms_auth)

        ignore_expired = 1 if kwargs.get('ignore_expired',True) else 0
        verify_flags = kwargs.get('verify_flags', 0)

        self.ms_auth.ignore_expired = ignore_expired
        self.ms_auth.verify_flags = verify_flags

        CAfile = kwargs.get('CAfile', None)
        CApath = kwargs.get('CApath', None)
        X509_set_extra_params(&self.ms_auth,
            kwargs.get('purpose', 7), # Default is PURPOSE_ANY
            <char *>CAfile if CAfile else <char *>0,
            <char *>CApath if CApath else <char *>0
        )

        sig = kwargs.get('sig', None)
        if sig:
            self.load_pkcs7_der(sig)

    def __del__(self):
        cleanup_ms_authcode(&self.ms_auth)

    def load_pkcs7_der(self, pkcs7_der):
        if load_pkcs7_der(&self.ms_auth, pkcs7_der, len(pkcs7_der)):
            return True
        return False

    def verify_digest(self):
        cdef ms_authcode_callback cb

        if not is_loaded(&self.ms_auth):
            raise Exception("PKCS#7 signature not loaded")

        error_list = []
        cb.callback = verify_callback
        cb.data = <void *><object>error_list
        if verify_p7(&self.ms_auth, &cb):
            return True, error_list
        return False, error_list

    def get_signers(self):
        return self._get_certs(True)

    def get_certs(self):
        return self._get_certs(False)

    cdef _get_certs(self, signers=True):
        cdef ms_authcode_callback cb
        cdef int i
        cdef int count
        if self.num_signers <= 0:
            return None

        if not is_loaded(&self.ms_auth):
            raise Exception("PKCS#7 signature not loaded")

        results = []

        cb.callback = certificate_callback
        count = self.num_signers if signers else self.num_certs
        for i in range(count):
            curr = {}
            cb.data = <void *><object>curr
            get_certificate(&self.ms_auth, 1 if signers else 0, i, &cb)
            if curr:
                results.append(curr)

        return results

    property num_signers:
        def __get__(self):
            if not is_loaded(&self.ms_auth):
                raise Exception("PKCS#7 signature not loaded")
            return self.ms_auth.num_signers

    property num_certs:
        def __get__(self):
            if not is_loaded(&self.ms_auth):
                raise Exception("PKCS#7 signature not loaded")
            return self.ms_auth.num_certs

    property pagehash_algorithm:
        def __get__(self):
            if not is_loaded(&self.ms_auth):
                raise Exception("PKCS#7 signature not loaded")
            if self.ms_auth.phtype == -1:
                return None
            return PyString_FromString(OBJ_nid2sn(self.ms_auth.phtype))

    property digest_algorithm:
        def __get__(self):
            if not is_loaded(&self.ms_auth):
                raise Exception("PKCS#7 signature not loaded")
            if self.ms_auth.mdtype == -1:
                return None
            return PyString_FromString(OBJ_nid2sn(self.ms_auth.mdtype))

    property digest:
        def __get__(self):
            cdef int size, mdtype
            mdtype = self.ms_auth.mdtype
            if not is_loaded(&self.ms_auth):
                raise Exception("PKCS#7 signature not loaded")
            if self.ms_auth.mdtype == -1:
                return None
            size = EVP_MD_size(EVP_get_digestbyname(OBJ_nid2sn(mdtype)))
            return PyString_FromStringAndSize(<char *>self.ms_auth.mdbuf, size)