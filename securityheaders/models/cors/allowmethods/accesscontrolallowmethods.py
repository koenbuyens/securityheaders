from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import *
from .accesscontrolallowmethodsdirective import AccessControlAllowMethodsDirective

@description('TODO')
@headername('access-control-allow-methods')
@headerref('https://fetch.spec.whatwg.org/')
class AccessControlAllowMethods(SecurityHeader):
    directive = AccessControlAllowMethodsDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlAllowMethodsDirective)

    def methods(self):
        if self.parsedstring:
            return self.keys()
        return []
