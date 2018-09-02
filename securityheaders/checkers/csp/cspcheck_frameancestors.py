from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckFrameAncestors(CSPCheck):
    
    def __init__(self, csp, function):
        self.csp = csp
        self.function = function
    
    def check(self):
        csp = self.csp
        if not csp:
            return []
                
        findings = []
    
        self.function(csp.parsedstring, self.checkframing, findings)
        return findings

    def checkframing(self, directive, directiveValues, findings):
        csp = self.csp
        description = "This directive tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking. The recommended value is 'none' or 'self'."
        for value in directiveValues:
            if directive == csp.directive.FRAME_ANCESTORS:
               if self.__notcontains_keyword__(value, csp.keyword.NONE) and self.__notcontains_keyword__(value, csp.keyword.SELF):
                   findings.append(Finding(csp.headerkey, FindingType.ALLOW_FROM,description,FindingSeverity.MEDIUM_MAYBE, directive, value))                  


    def __notcontains_keyword__(self, value, keyword):
         return keyword != value and keyword.value not in str(value)
