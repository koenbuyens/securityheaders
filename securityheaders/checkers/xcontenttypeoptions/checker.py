from securityheaders.models.xcontenttypeoptions import XContentTypeOptions

from securityheaders.checkers import Checker

class XContentTypeOptionsChecker(Checker):
    def __init__(self):
        pass

    def getxcontenttypeoptions(self, headers):
         return self.extractheader(headers, XContentTypeOptions) 
