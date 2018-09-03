from securityheaders.models.cors import AccessControlExposeHeaders
from securityheaders.checkers import Checker

class AccessControlExposeHeadersChecker(Checker):
    def __init__(self):
        pass

    def getexposeheaders(self, headers):
        return self.extractheader(headers, AccessControlExposeHeaders)


