from securityheaders.checkers import HeaderDeprecatedChecker
from securityheaders.models import XContentSecurityPolicy

class XCSPDeprecatedChecker(HeaderDeprecatedChecker):
    def check(self, headers, options=[]):
        return HeaderDeprecatedChecker.mycheck(self, headers, XContentSecurityPolicy.headerkey)
