from securityheaders.models import SecurityHeader
from securityheaders.models.hsts import HSTSDirective
from securityheaders.models.annotations import *

@requiredheader
@description('This header strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS. The recommended value us "strict-transport-security: max-age=31536000; includeSubDomains".')
@headername('strict-transport-security')
@headerref('http://tools.ietf.org/html/rfc6797')
class HSTS(SecurityHeader):
    directive = HSTSDirective

    def __init__(self, unparsedstring):
       SecurityHeader.__init__(self, unparsedstring, HSTSDirective)


    def includesubdomains(self):
        try:
            return HSTSDirective.INCLUDESUBDOMAINS in self.parsedstring
        except:
            return False


    def preload(self):
        try:
            return HSTSDirective.PRELOAD in self.parsedstring
        except error:
            return False  


    def maxAge(self):
        result = None
        if self.parsedstring and HSTSDirective.MAX_AGE in self.parsedstring:
            if isinstance(self.parsedstring[HSTSDirective.MAX_AGE], list):
                try:
                    result = int(self.parsedstring[HSTSDirective.MAX_AGE][0])
                except:
                    result = None
            else:
                result = int(self.parsedstring[HSTSDirective.MAX_AGE])
        return result
