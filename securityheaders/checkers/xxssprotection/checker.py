from securityheaders.checkers import Checker
from securityheaders.models.xxssprotection import XXSSProtection

class XXSSProtectionChecker(Checker):
    def __init__(self):
        pass

    def getxxss(self, headers):
         return self.extractheader(headers, XXSSProtection) 

