from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import description, headername

@description('Deprecated header for a Content-Security-Policy.')
@headername('x-content-security-policy')
class XContentSecurityPolicy(SecurityHeader):
    directive = None

    def __init__(self, unparsedstring):
        self.parsedstring = unparsedstring
        self.parsed = False
