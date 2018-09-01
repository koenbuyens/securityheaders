from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import *
from .accesscontrolalloworigindirective import AccessControlAllowOriginDirective

@description('TODO')
@headername('access-control-allow-origin')
@headerref('https://fetch.spec.whatwg.org/')
class AccessControlAllowOrigin(SecurityHeader):
    directive = AccessControlAllowOriginDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlAllowOriginDirective)

    def origins(self):
        return self.keys()

    def isstar(self):
        return self.origins() and self.origins()[0] is AccessControlAllowOriginDirective.STAR

    def isnull(self):
        return self.origins() and self.origins()[0] is AccessControlAllowOriginDirective.NULL

