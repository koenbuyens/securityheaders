from securityheaders.models import SecurityHeader
from securityheaders.models.xframeoptions import XFrameOptionsDirective
from securityheaders.models.annotations import *

@requiredheader
@description('This header tells the browser whether the site can be framed. Not allowing framing defends against clickjacking attacks.')
@headername('x-frame-options')
@headerref('https://tools.ietf.org/html/rfc7034')
class XFrameOptions(SecurityHeader):
    directive = XFrameOptionsDirective

    def __init__(self, unparsedstring):
       SecurityHeader.__init__(self, unparsedstring, XFrameOptionsDirective)

    def deny(self):
        try:
            return XFrameOptionsDirective.DENY in self.parsedstring
        except:
            return False


    def sameorigin(self):
        try:
            return XFrameOptionsDirective.SAMEORIGIN in self.parsedstring
        except:
            return False

    def allowfrom(self):
        result = None
        if self.parsedstring and XFrameOptionsDirective.ALLOW_FROM in self.parsedstring:
            if isinstance(self.parsedstring[XFrameOptionsDirective.ALLOW_FROM], list):
                if len(self.parsedstring[XFrameOptionsDirective.ALLOW_FROM]) > 0:
                    result = self.parsedstring[XFrameOptionsDirective.ALLOW_FROM][0]
                else:
                    result = ""
            else:
                result = self.parsedstring[XFrameOptionsDirective.ALLOW_FROM]
        return result
