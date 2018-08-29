from securityheaders.models import SecurityHeader
from accesscontrolmaxagedirective import AccessControlMaxAgeDirective
from securityheaders.models.annotations import *

@description('TODO')
@headername('access-control-max-age')
@headerref('https://fetch.spec.whatwg.org/')
class AccessControlMaxAge(SecurityHeader):
    directive = AccessControlMaxAgeDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, AccessControlMaxAgeDirective)


    def maxage(self):
        if self.parsedstring and len(self.parsedstring) > 0:
            result = self.parsedstring.keys()[0]
            return int(result)
        return None
