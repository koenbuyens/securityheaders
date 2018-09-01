from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

try:
    from urlparse import urlparse
except ModuleNotFoundError:
    from urllib.parse import urlparse #python3

import ipaddress

class CSPCheckIPSource(CSPCheck):
    def __init__(self, csp, function):
        self.csp = csp
        self.function = function
    
    def check(self):
        csp = self.csp
        if not csp:
            return []
                
        findings = []

        self.function(csp.parsedstring, self.checkIP, findings)
        return findings
    
    def checkIP(self, directive, directiveValues, findings):
        csp = self.csp
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
                    findings.append(Finding(csp.headerkey,FindingType.IP_SOURCE, directive.value + ' directive allows localhost as source. Please make sure to remove this in production environments.',FindingSeverity.INFO, directive, value))
                else:
                    findings.append(Finding(csp.headerkey,FindingType.IP_SOURCE, directive.value + ' directive has an IP-Address as source: ' + ipString + ' (will be ignored by browsers!). ', FindingSeverity.INFO, directive, value))


