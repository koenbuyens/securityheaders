from securityheaders.models.expectct import ExpectCT
from securityheaders.checkers import Checker

class ExpectCTChecker(Checker):
    def __init__(self):
        pass

    def getexpectct(self, headers):
         return self.extractheader(headers, ExpectCT)
