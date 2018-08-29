from securityheaders.models import SecurityHeader
from accesscontrolexposeheadersdirective import AccessControlExposeHeadersDirective
from securityheaders.models.annotations import *

@description('TODO')
@headername('access-control-expose-headers')
@headerref('https://fetch.spec.whatwg.org/')
class AccessControlExposeHeaders(SecurityHeader):
    directive = AccessControlExposeHeadersDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlExposeHeadersDirective)

    def headers(self):
        if self.parsedstring:
            return self.parsedstring.keys()
        return []    
