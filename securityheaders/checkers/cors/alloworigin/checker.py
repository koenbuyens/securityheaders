from securityheaders.models.cors import AccessControlAllowOrigin
from securityheaders.checkers import Checker

class AccessControlAllowOriginChecker(Checker):
    def __init__(self):
        pass

    def getorigins(self, headers):
        return self.extractheader(headers, AccessControlAllowOrigin)


