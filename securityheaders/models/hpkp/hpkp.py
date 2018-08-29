from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import *

@description('HTTP Public Key Pinning (HPKP) is a trust on first use security mechanism which protects HTTPS websites from impersonation using fraudulent certificates issued by compromised certificate authorities. The security context or pinset data is supplied by the site or origin.')
@headername('public-key-pins')
@headerref('https://tools.ietf.org/html/rfc7469')
class PublicKeyPins(SecurityHeader):
    directive = None

    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
