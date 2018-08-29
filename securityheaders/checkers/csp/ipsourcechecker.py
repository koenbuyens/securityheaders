from securityheaders import Util
from urlparse import urlparse
import ipaddress

# checks whether allowed source is e.g. localhost
from securityheaders.models.csp import CSP
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPIPSourceChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp:
            return []

        findings = []

        self.applyCheckFunktionToDirectives(csp.parsedstring, self.checkIP, findings)
        return findings

    def checkIP(self, directive, directiveValues, findings):
        for value in directiveValues:
            url = '//' + Util.getSchemeFreeUrl(value)
            host = urlparse(url).netloc
            ip = None
            validip = True
             
            try:
                ip = ipaddress.ip_address(u''+host)
            except ValueError:
                validip = False
            if validip:
                ipString = str(ip) + ''

                if '127.0.0.1' in ipString:
                    findings.append(Finding(CSP.headerkey,FindingType.IP_SOURCE, directive.value + ' directive allows localhost as source. Please make sure to remove this in production environments.',FindingSeverity.INFO, directive, value))
                else:
                    findings.append(Finding(CSP.headerkey,FindingType.IP_SOURCE, directive.value + ' directive has an IP-Address as source: ' + ipString + ' (will be ignored by browsers!). ', FindingSeverity.INFO, directive, value))

