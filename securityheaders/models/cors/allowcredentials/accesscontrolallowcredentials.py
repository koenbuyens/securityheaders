from securityheaders.models import SecurityHeader
from accesscontrolallowcredentialsdirective import AccessControlAllowCredentialsDirective
from securityheaders.models.annotations import description, headername

@description('TODO')
@headername('access-control-allow-credentials')
class AccessControlAllowCredentials(SecurityHeader):
    directive = AccessControlAllowCredentialsDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlAllowCredentialsDirective)


    def value(self):
        if self.parsedstring and len(self.parsedstring) > 0:
            return self.parsedstring.keys()[0]
        return None
