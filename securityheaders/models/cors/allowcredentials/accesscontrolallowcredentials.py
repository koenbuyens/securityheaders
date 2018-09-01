from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import *
from .accesscontrolallowcredentialsdirective import AccessControlAllowCredentialsDirective

@description('TODO')
@headername('access-control-allow-credentials')
@headerref('https://fetch.spec.whatwg.org/')
class AccessControlAllowCredentials(SecurityHeader):
    directive = AccessControlAllowCredentialsDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlAllowCredentialsDirective)


    def value(self):
        if self.parsedstring and len(self.parsedstring) > 0:
            return self.keys()[0]
        return None
