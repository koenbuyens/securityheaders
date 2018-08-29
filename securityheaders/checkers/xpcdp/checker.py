from securityheaders.models.xpcdp import XPermittedCrossDomainPolicies
from securityheaders.checkers import Checker

class XPermittedCrossDomainPolicyChecker(Checker):
    def __init__(self):
        pass

    def getxpcdp(self, headers):
         return self.extractheader(headers, XPermittedCrossDomainPolicies)
