from securityheaders.models import SecurityHeader
from securityheaders.models.xxssprotection import XXSSProtectionDirective
from securityheaders.models.annotations import *

@requiredheader
@description('This header sets the configuration for the cross-site scripting filter built into most browsers. The recommended value is "X-XSS-Protection: 1; mode=block')
@headername('x-xss-protection')
@headerref('https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/dd565647(v=vs.85)')
class XXSSProtection(SecurityHeader):
    directive = XXSSProtectionDirective

    def __init__(self, unparsedstring):
       SecurityHeader.__init__(self, unparsedstring, XXSSProtectionDirective)

    def one(self):
        try:
            return XXSSProtectionDirective.ONE in self.parsedstring
        except error:
            return False  

    def zero(self):
        try:
            return XXSSProtectionDirective.ZERO in self.parsedstring
        except error:
            return False

    def mode(self):
        result = None
        if self.parsedstring and XXSSProtectionDirective.MODE in self.parsedstring:
            if isinstance(self.parsedstring[XXSSProtectionDirective.MODE], list):
                if len(self.parsedstring[XXSSProtectionDirective.MODE]) > 0:
                    result = self.parsedstring[XXSSProtectionDirective.MODE][0]
                else:
                    result = ""
            else:
                result = self.parsedstring[XXSSProtectionDirective.MODE]
        return result  

    def report(self):
        result = None
        if self.parsedstring and XXSSProtectionDirective.REPORT in self.parsedstring:
            if isinstance(self.parsedstring[XXSSProtectionDirective.REPORT], list):
                if len(self.parsedstring[XXSSProtectionDirective.REPORT]) > 0:
                    result = self.parsedstring[XXSSProtectionDirective.REPORT][0]
                else:
                    result = ""
            else:
                result = self.parsedstring[XXSSProtectionDirective.REPORT]
        return result 
