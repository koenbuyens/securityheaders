from securityheaders.models.hsts import HSTS
from securityheaders.checkers import Checker

class HSTSChecker(Checker):
    def __init__(self):
        pass

    def gethsts(self, headers):
         return self.extractheader(headers, HSTS) 
