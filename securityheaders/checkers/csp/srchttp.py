
#checks wheter URIs are NOT http:
from securityheaders.models.csp import CSP
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPSCRHTTPChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp:
            return []

        findings = []

        self.applyCheckFunktionToDirectives(csp.parsedstring, self.checksrchttp, findings)
        return findings

    def checksrchttp(self, directive, directiveValues, findings):
        for value in directiveValues:
            description = None
            if directive == CSP.directive.REPORT_URI:
                description = 'Use HTTPS to send violation reports securely.'
            else:
                description = 'Allow only resources downloaded over HTTPS.'
            if value.startswith('http://'):
                findings.append(Finding(CSP.headerkey, FindingType.SRC_HTTP,description,FindingSeverity.MEDIUM, directive, value))


