from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import *
from .accesscontrolallowheadersdirective import AccessControlAllowHeadersDirective

@description('TODO')
@headername('access-control-allow-headers')
@headerref('https://fetch.spec.whatwg.org/')
class AccessControlAllowHeaders(SecurityHeader):
    directive = AccessControlAllowHeadersDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlAllowHeadersDirective)

    def headers(self):
        if self.parsedstring:
            return self.keys()
        return []
