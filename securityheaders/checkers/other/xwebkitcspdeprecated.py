from securityheaders.checkers import HeaderDeprecatedChecker
from securityheaders.models import XWebKitCSP

class XWebKitCSPDeprecatedChecker(HeaderDeprecatedChecker):
    def check(self, headers, options=[]):
        return HeaderDeprecatedChecker.mycheck(self, headers, XWebKitCSP.headerkey)
