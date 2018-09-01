from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import *
from .accesscontrolexposeheadersdirective import AccessControlExposeHeadersDirective

@description('TODO')
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
