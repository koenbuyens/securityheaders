from securityheaders.models.cors import AccessControlAllowOriginDirective, AccessControlAllowOrigin, AccessControlAllowCredentials
from securityheaders.checkers import FindingSeverity, Finding, FindingType
from securityheaders.checkers.cors import AccessControlAllowCredentialsChecker
from .checker import AccessControlAllowOriginChecker

class AccessControlAllowOriginHTTPCredsChecker(AccessControlAllowOriginChecker, AccessControlAllowCredentialsChecker):
    def check(self, headers, opt_options=dict()):
        origins = self.getorigins(headers)
        hascreds = self.getallowcreds(headers)
        findings = []

        if hascreds and hascreds.value() and origins:           
            for origin in origins.origins():
                if origin.startswith('http:'):
                    findings.append(Finding(AccessControlAllowOrigin.headerkey, FindingType.HTTP_ORIGIN, str(AccessControlAllowOrigin.headerkey) + " should be HTTPS rather than HTTP when " + str(AccessControlAllowCredentials.headerkey) + " is true",FindingSeverity.LOW, origin, None))
        return findings

