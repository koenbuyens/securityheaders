#checks whether data: or http: has been used
#  allowing URLs that start with data: are equivalent to unsafe-inline.
from securityheaders.models.csp import CSP
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPPlainUrlSchemesChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        findings = []
        csp = self.getcsp(headers) 

        if not csp or not csp.parsedstring:
            return findings


        directivesToCheck = csp.getEffectiveDirectives(CSP.DIRECTIVES_CAUSING_XSS)
        for directive in directivesToCheck:
            values = []
            if directive in csp.parsedstring:
                values = csp[directive]
            for value in values:
                if value in CSP.URL_SCHEMES_CAUSING_XSS:
                    findings.append(Finding(CSP.headerkey, FindingType.PLAIN_URL_SCHEMES,  value + ' URI in ' + directive.value + ' allows the execution of unsafe scripts.',FindingSeverity.HIGH, directive, value))

        return findings

