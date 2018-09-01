from securityheaders.models.cors import AccessControlMaxAgeDirective, AccessControlMaxAge
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from .checker import AccessControlMaxAgeChecker

class AccessControlMaxAgeTooLongChecker(AccessControlMaxAgeChecker):
    def check(self, headers, opt_options=dict()):
        maxage = self.getmaxage(headers)
        if maxage and maxage.maxage() and maxage.maxage() > 1800:
                return [Finding(AccessControlMaxAge.headerkey, FindingType.MAX_AGE_TOO_LONG, str(AccessControlMaxAge.headerkey) +  " set to a too large value. This header is used by the server to explicitly instruct browsers to cache responses to CORS requests. An excessively long cache timeout increases the risk that changes to a server's CORS policy will not be honored as they still use a cached response.",FindingSeverity.LOW, AccessControlMaxAgeDirective, str(maxage.maxage()))]
        return []
