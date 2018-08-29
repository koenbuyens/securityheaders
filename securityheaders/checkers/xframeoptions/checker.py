from securityheaders.models.xframeoptions import XFrameOptions
from securityheaders.checkers import Checker

class XFrameOptionsChecker(Checker):
    def __init__(self):
        pass

    def getxframeoptions(self, headers):
         return self.extractheader(headers, XFrameOptions) 
