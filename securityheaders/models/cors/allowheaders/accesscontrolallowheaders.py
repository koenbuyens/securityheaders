from securityheaders.models import SecurityHeader
from accesscontrolallowheadersdirective import AccessControlAllowHeadersDirective
from securityheaders.models.annotations import description, headername

@description('TODO')
@headername('access-control-allow-headers')
class AccessControlAllowHeaders(SecurityHeader):
    directive = AccessControlAllowHeadersDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlAllowHeadersDirective)

    def headers(self):
        if self.parsedstring:
            return self.parsedstring.keys()
        return []
