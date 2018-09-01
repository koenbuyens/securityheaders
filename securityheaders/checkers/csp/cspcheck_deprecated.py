from securityheaders.checkers import Finding, FindingType, FindingSeverity
from .cspcheck import CSPCheck

class CSPCheckDeprecated(CSPCheck):
    
    def __init__(self, csp):
        self.csp = csp
    
    def check(self):
        csp = self.csp
        if not csp or not csp.parsedstring:
            return []
            
        findings = []
        if csp.directive.REPORT_URI in csp.parsedstring:
            findings.append(Finding(csp.headerkey,FindingType.DEPRECATED_DIRECTIVE,'report-uri is deprecated in CSP3. Please use the report-to directive instead.', FindingSeverity.INFO, csp.directive.REPORT_URI))
            return findings
        return []
