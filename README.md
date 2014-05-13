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
from authenticode.pe import PEAuthenticode
pea = PEAuthenticode(CApath='/etc/ssl/certs', ignore_expired=True)
if pea.verify_pe('vmbus.sys'):
    print "Verified"
print pea.get_verify_errors()
print pea.get_signers()
print pea.get_certs()
```

If you have an alternative method of obtaining the pkcs7 blob
for verification:
```python
pea = PEAuthenticode(CApath='/etc/ssl/certs')
if pea.verify_digest(pkcs7der):
    print "Verified"
```

#####Apologies
I feel like this is a bit of a hack. Feel free to make it prettier.

###TODO
CRL's, page_hash. Dunno if it works on python3. Tests. Doc.. the usual.
