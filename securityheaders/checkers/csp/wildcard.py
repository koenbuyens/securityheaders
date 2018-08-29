#checks whether * has been used
#The directive 'script-src' should not be set to *, as it allows loading of arbitrary JavaScript. T
#The directive 'object-src' should not be set to *, as it allows loading of arbitrary plugins that can execute JavaScript (e.g. Flash).

from securityheaders import Util

from securityheaders.models.csp import CSP
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPWildCardChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp or not csp.parsedstring:
            return []

        findings = []

        directivesToCheck = csp.getEffectiveDirectives(CSP.DIRECTIVES_CAUSING_XSS)

        for directive in directivesToCheck:
            values = []
            if directive in csp.parsedstring:
                values = csp[directive]
            
            for value in values:
                url = Util.getSchemeFreeUrl(value)
                if '*' in url and len(url) == 1:
                    findings.append(Finding(csp.headerkey, FindingType.PLAIN_WILDCARD, directive.value + ' should not allow \'*\' as source. This may enable execution of malicious JavaScript.',FindingSeverity.HIGH, directive, value))

        return findings

