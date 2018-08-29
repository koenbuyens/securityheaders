from securityheaders.checkers import Checker
from securityheaders.models.cors.allowcredentials import AccessControlAllowCredentials

class AccessControlAllowCredentialsChecker(Checker):
    def __init__(self):
        pass

    def getallowcreds(self, headers):
        return self.extractheader(headers, AccessControlAllowCredentials)
