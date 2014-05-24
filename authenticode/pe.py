"""This module can be used to verify Microsoft PE files.

It is based on code from osslsigncode.c,v 1.6
http://sourceforge.net/projects/osslsigncode/
by Per Allansson <pallansson@gmail.com>
"""
import _authenticode
import pefile
import hashlib

from struct import unpack
from functools import partial
from binascii import hexlify

class PEAuthenticode(object):
    def __init__(self, **kwargs):
        self._auth = _authenticode.PEAuthenticode(**kwargs)
        self._verified = None
        self._verify_errors = None
        self._pe_calced_digest = None
        self._pe_expected_digest = None
        self._pkcs7_der = None

    def verify_file(self, filename, **kwargs):
        pe = pefile.PE(filename, fast_load=True)
        return self.verify_pe(filename, **kwargs)

    def verify_pe(self, pe, stop_at_signature=False):
        index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        CertificateTable = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
        self.file_offset = CertificateTable.VirtualAddress
        self.size = CertificateTable.Size
        if not file_offset or not size:
            return None

        with open(filename, 'rb') as fd:
            fd.seek(self.file_offset)
            data = fd.read(self.size)
            self._pkcs7_der = pkcs7_der = data[8:]
            self.verify_digest(pkcs7_der)

            digest = {
                'SHA1': hashlib.sha1,
                'SHA256': hashlib.sha256,
                'MD5': hashlib.md5,
            }.get(self._auth.digest_algorithm)()

            for blob in self._pe_hash_input(pe, fd, stop_at_signature):
                digest.update(blob)

            self._pe_calced_digest = digest.digest()

            digestmatch = self._auth.digest == digest.digest()
            return digestmatch and self.is_digest_verified()
        return False

    def verify_digest(self, pkcs7_der):
        if not self._auth.load_pkcs7_der(pkcs7_der):
            raise Exception("Could not load data as PKCS#7")
        verified, errors = self._auth.verify_digest()
        self._verified = verified
        self._verify_errors = errors

        return verified

    def get_verify_errors(self):
        if self._verified is None:
            raise Exception("PKCS#7 data not loaded")

        return self._verify_errors

    def get_signers(self):
        if self._verified is None:
            raise Exception("PKCS#7 data not loaded")
        return self._auth.get_signers()

    def get_certs(self):
        if self._verified is None:
            raise Exception("PKCS#7 data not loaded")
        return self._auth.get_certs()

    def is_digest_verified(self):
        if self._verified is None:
            raise Exception("PKCS#7 data not loaded")
        return self._verified

    def get_pkcs7_der(self):
        return self._pkcs7_der

    def _pe_hash_input(self, pe, fd, stop_at_signature=False):
        offset = pe.OPTIONAL_HEADER.get_file_offset()
        offset += pe.OPTIONAL_HEADER.get_field_relative_offset('CheckSum')

        headers = pe.get_data(0, pe.OPTIONAL_HEADER.SizeOfHeaders)

        # According to MS Authenticode Spec:
        # 1. Hash headers up to checksum field
        yield headers[0:offset]
        # 2. Skip the checksum
        lastoffset = offset + 4

        index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        CertificateTable = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
        offset = CertificateTable.get_file_offset()
        sig_offset = CertificateTable.VirtualAddress

        # 3. Continue hashing headers
        yield headers[lastoffset:offset]
        # 4. Skip the Data Directory entry for the certificate.
        # 5. Continue hashing headers (Up to SizeOfHeaders)
        yield headers[offset+8:pe.OPTIONAL_HEADER.SizeOfHeaders]

        # 6. Hash sections in order in which they appear in the file.
        #    (non zero sized sections)
        sections = [ s for s in pe.sections if s.SizeOfRawData ]
        sections = sorted(sections, key=lambda s: s.PointerToRawData)
        for s in sections:
            yield s.get_data()

        sect_end = max([ s.PointerToRawData+s.SizeOfRawData for s in pe.sections ])
        sig_offset -= sect_end
        if sig_offset < 0:
            raise Exception("Digital signature is not in appended data.")

        # 7. Get remainder
        # 7(i). Yield any data between the last section and the signature
        fd.seek(sect_end)
        if sig_offset:
            yield fd.read(sig_offset)

        if stop_at_signature:
            return

        sig_hdr = fd.read(8)

        size, hdr_sig = unpack("<II", sig_hdr)
        fd.seek(size, 1) # SEEK_CUR

        # 7(ii). Get the rest.
        for data in iter(partial(fd.read, 0x100000), ''):
            yield data

