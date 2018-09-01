from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckSrcHttp(CSPCheck):
    
    def __init__(self, csp, function):
        self.csp = csp
        self.function = function
    
    def check(self):
        csp = self.csp
        if not csp:
            return []
                
        findings = []
    
        self.function(csp.parsedstring, self.checksrchttp, findings)
        return findings

    def checksrchttp(self, directive, directiveValues, findings):
        csp = self.csp
        for value in directiveValues:
            description = None
            if directive == csp.directive.REPORT_URI:
                description = 'Use HTTPS to send violation reports securely.'
            else:
                description = 'Allow only resources downloaded over HTTPS.'
            if value.startswith('http://'):
                findings.append(Finding(csp.headerkey, FindingType.SRC_HTTP,description,FindingSeverity.MEDIUM, directive, value))
