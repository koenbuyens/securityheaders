from securityheaders.checkers import HeaderDeprecatedChecker
from securityheaders.models import PublicKeyPins

class PublicKeyPinsDeprecatedChecker(HeaderDeprecatedChecker):
    def check(self, headers, options=[]):
        return HeaderDeprecatedChecker.mycheck(self, headers, PublicKeyPins.headerkey)
