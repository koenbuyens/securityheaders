import re

from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck


class CSPCheckNonceLength(CSPCheck):
    def __init__(self, csp, function):
        self.csp = csp
        self.function = function
    
    def check(self, opt_options=dict()):
        csp = self.csp
        if not csp:
            return []
                
        findings = []

        self.function(csp.parsedstring, self.checkNonce, findings)
        return findings
    
    
    def checkNonce(self, directive, directiveValues, findings):
        nonce_pattern = re.compile("^'nonce-(.+)'$")
        for value in directiveValues:
            value = str(value)
            match = nonce_pattern.search(value)
            #nonce value starts with nonce- but does not have an actual value
            if not bool(match) and "nonce-" in value:
                findings.append(Finding(self.csp.headerkey,FindingType.NONCE_LENGTH,'Nonces should be at least 8 characters long.',FindingSeverity.MEDIUM, directive, value))
            #no nonce value in the directive value
            if not bool(match):
                continue
            #nonce value in the directive value
            else:
                #get the value of the nonce; i.e. everything after nonce-
                nonceValue = match.group(1)
                if len(nonceValue) < 8:
                    findings.append(Finding(self.csp.headerkey,FindingType.NONCE_LENGTH,'Nonces should be at least 8 characters long.',FindingSeverity.MEDIUM, directive, value))
                if not self.csp.isNonce(value, True):
                    findings.append(Finding(self.csp.headerkey,FindingType.NONCE_LENGTH,'Nonces should only use the base64 charset.',FindingSeverity.INFO, directive, value))



