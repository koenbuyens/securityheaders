from securityheaders.models import SecurityHeader
from securityheaders.models.annotations import *
from .accesscontrolmaxagedirective import AccessControlMaxAgeDirective

@description('TODO')
@headername('access-control-max-age')
@headerref('https://fetch.spec.whatwg.org/')
class AccessControlMaxAge(SecurityHeader):
    directive = AccessControlMaxAgeDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlMaxAgeDirective)


    def maxage(self):
        if self.parsedstring and len(self.parsedstring) > 0:
            result = self.keys()[0]
            return int(result)
        return None
