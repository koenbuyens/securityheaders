from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckPlainUrlSchemes(CSPCheck):
    
    def __init__(self, csp, effectiveDirectiveValues):
        self.csp = csp
        self.values = effectiveDirectiveValues

    def check(self):
        csp = self.csp
        if not csp or not csp.parsedstring:
            return []
        findings = []
        directivesToCheck = self.values
        for directive in directivesToCheck:
            values = []
            if directive in csp.parsedstring:
                values = csp[directive]
            for value in values:
                if value in csp.URL_SCHEMES_CAUSING_XSS:
                    findings.append(Finding(csp.headerkey, FindingType.PLAIN_URL_SCHEMES,  value + ' URI in ' + directive.value + ' allows the execution of unsafe scripts.',FindingSeverity.HIGH, directive, value))

        return findings
