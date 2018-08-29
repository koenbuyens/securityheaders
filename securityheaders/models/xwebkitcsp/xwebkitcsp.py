from securityheaders.models import Header
from securityheaders.models.annotations import *

@description('Deprecated header for a Content-Security-Policy.')
@headername('x-webkit-csp')
@headerref('http://www.w3.org/TR/CSP/')
class XWebKitCSP(Header):
    directive = None

    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
