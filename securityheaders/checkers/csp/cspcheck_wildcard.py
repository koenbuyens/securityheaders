from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckWildCard(CSPCheck):
    
    def __init__(self, csp):
        self.csp = csp
    
    def check(self):
        csp = self.csp
        if not csp or not csp.parsedstring:
            return []
    
        findings = []

        directivesToCheck = csp.getEffectiveDirectives(csp.DIRECTIVES_CAUSING_XSS)
            
        for directive in directivesToCheck:
            values = []
            if directive in csp.parsedstring:
                values = csp[directive]
            
            for value in values:
                url = Util.getSchemeFreeUrl(value)
                if '*' in url and len(url) == 1:
                    findings.append(Finding(csp.headerkey, FindingType.PLAIN_WILDCARD, directive.value + ' should not allow \'*\' as source. This may enable execution of malicious JavaScript.',FindingSeverity.HIGH, directive, value))

        return findings
