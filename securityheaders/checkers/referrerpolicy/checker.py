from securityheaders.models.referrerpolicy import ReferrerPolicy
from securityheaders.checkers import Checker

class ReferrerPolicyChecker(Checker):
    def __init__(self):
        pass

    def getreferrerpolicy(self, headers):
         return self.extractheader(headers, ReferrerPolicy) 
