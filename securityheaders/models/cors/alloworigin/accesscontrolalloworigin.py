from securityheaders.models import SecurityHeader
from accesscontrolalloworigindirective import AccessControlAllowOriginDirective
from securityheaders.models.annotations import *

@description('TODO')
@headername('access-control-allow-origin')
@headerref('https://fetch.spec.whatwg.org/')
class AccessControlAllowOrigin(SecurityHeader):
    directive = AccessControlAllowOriginDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlAllowOriginDirective)

    def origins(self):
        if self.parsedstring:
            return self.parsedstring.keys()
        return []

    def isstar(self):
        return self.origins() and self.origins()[0] is AccessControlAllowOriginDirective.STAR

    def isnull(self):
        return self.origins() and self.origins()[0] is AccessControlAllowOriginDirective.NULL

