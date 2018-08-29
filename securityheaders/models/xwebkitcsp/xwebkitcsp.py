from securityheaders.models import Header
from securityheaders.models.annotations import description, headername

@description('Deprecated header for a Content-Security-Policy.')
@headername('x-webkit-csp')
class XWebKitCSP(Header):
    directive = None

    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
