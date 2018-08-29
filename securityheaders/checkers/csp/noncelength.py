#checks nonce length to be at least 8 characters
#checks nonce length to be base64
from securityheaders.models.csp import CSP
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

import re

class CSPNonceLengthChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp:
            return []

        findings = []

        self.applyCheckFunktionToDirectives(csp.parsedstring, self.checkNonce, findings)
        return findings


    def checkNonce(self, directive, directiveValues, findings):
        nonce_pattern = re.compile("^'nonce-(.+)'$")
        for value in directiveValues:
            value = str(value)
            match = nonce_pattern.search(value)
            #nonce value starts with nonce- but does not have an actual value
            if not bool(match) and "nonce-" in value:
                findings.append(Finding(CSP.headerkey,FindingType.NONCE_LENGTH,'Nonces should be at least 8 characters long.',FindingSeverity.MEDIUM, directive, value))
            #no nonce value in the directive value
            if not bool(match):
                continue
            #nonce value in the directive value
            else:
                #get the value of the nonce; i.e. everything after nonce-
                nonceValue = match.group(1)
                if len(nonceValue) < 8:
                    findings.append(Finding(CSP.headerkey,FindingType.NONCE_LENGTH,'Nonces should be at least 8 characters long.',FindingSeverity.MEDIUM, directive, value))
                if not CSP.isNonce(value, True):
                    findings.append(Finding(CSP.headerkey,FindingType.NONCE_LENGTH,'Nonces should only use the base64 charset.',FindingSeverity.INFO, directive, value))


