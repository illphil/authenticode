"""This module can be used to carve out pkcs7 der structures from
files (potentially corrupt files for example)

It is based on code from osslsigncode.c,v 1.6
http://sourceforge.net/projects/osslsigncode/
by Per Allansson <pallansson@gmail.com>
"""
import re
import _authenticode

from struct import unpack
from functools import partial

def _extract_pkcs7(fd, offset, size, readsize):
    seek_restore = fd.tell()
    sig_offset = seek_restore - readsize + offset
    if sig_offset < 0:
        return None
    fd.seek(sig_offset)
    pkcs7_der = fd.read(size)

    ds = _authenticode.PEAuthenticode()
    loaded = False
    try:
        loaded = ds.load_pkcs7_der(pkcs7_der)
    except:
        pass

    fd.seek(seek_restore)

    return pkcs7_der if loaded else False

def carve_pkcs7(filename, readsize = 0x100000):
    with open(filename, 'rb') as fd:
        rex_sighdr = re.compile('(....)\x00\x02\x02\x00')

        for buff in iter(partial(fd.read, readsize), ''):
            buff_offset = 0
            while 1:
                m = rex_sighdr.search(buff, buff_offset)
                if m is None:
                    if len(buff) == readsize:
                        fd.seek(-7, 1) # SEEK_CUR
                    break
                sig_size, = unpack("<I", m.group(1))
                data = _extract_pkcs7(fd, m.end(), sig_size, len(buff))
                if data is not None and data:
                    yield data
                buff_offset = m.start() + 1
