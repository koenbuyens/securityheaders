from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import *
from .accesscontrolexposeheadersdirective import AccessControlExposeHeadersDirective

@description('An application can expose additional HTTP response headers to JavaScript by setting the Access-Control-Expose-Headers header to header names that need to be exposed.')
@headername('access-control-expose-headers')
@headerref('https://fetch.spec.whatwg.org/')
class AccessControlExposeHeaders(SecurityHeader):
    directive = AccessControlExposeHeadersDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlExposeHeadersDirective)

    def headers(self):
        if self.parsedstring:
            return self.keys()
        return []   

    def __repr__(self):
        return ", ".join(self.headers()) 
