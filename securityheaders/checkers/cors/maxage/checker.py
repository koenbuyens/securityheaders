from securityheaders.models.cors import AccessControlMaxAge
from securityheaders.checkers import Checker

class AccessControlMaxAgeChecker(Checker):
    def __init__(self):
        pass

    def getmaxage(self, headers):
        return self.extractheader(headers, AccessControlMaxAge)


