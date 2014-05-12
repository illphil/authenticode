authenticode
============
This module can be used to verify Microsoft PE files.

It is based on code from osslsigncode.c,v 1.6
http://sourceforge.net/projects/osslsigncode/
by Per Allansson <pallansson@gmail.com>

In fact much of the code in this is almost as-is from that tool, 
however functionality relating to PE verification was factored out
to facilitate the use of cython as well as removal of some functionality
that could be performed by pefile such as the extraction of data to be
hashed.

###Example usage
```python
from authenticode.authenticode import PEAuthenticode
pea = PEAuthenticode(CApath='/etc/ssl/certs')
if pea.verify_pe('vmbus.sys'):
    print "Verified"
```

If you have an alternative method of obtaining the pkcs7 blob
for verification:
```python
pea = PEAuthenticode(CApath='/etc/ssl/certs')
if pea.verify_digest(pkcs7der):
    print "Verified"
```

###TODO
CRL's, page_hash
