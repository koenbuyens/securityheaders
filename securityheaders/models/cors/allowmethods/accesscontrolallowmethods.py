from securityheaders.models import SecurityHeader
from accesscontrolallowmethodsdirective import AccessControlAllowMethodsDirective
from securityheaders.models.annotations import description, headername

@description('TODO')
@headername('access-control-allow-methods')
class AccessControlAllowMethods(SecurityHeader):
    directive = AccessControlAllowMethodsDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlAllowMethodsDirective)

    def methods(self):
        if self.parsedstring:
            return self.parsedstring.keys()
        return []
