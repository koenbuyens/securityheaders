from securityheaders.models.cors import AccessControlAllowOriginDirective, AccessControlAllowOrigin
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from .checker import AccessControlAllowOriginChecker

class AccessControlAllowOriginNullChecker(AccessControlAllowOriginChecker):
    def check(self, headers, opt_options=dict()):
        origins = self.getorigins(headers)
        if origins and origins.isnull():
            return [Finding(AccessControlAllowOrigin.headerkey, FindingType.NULL_ORIGIN, str(AccessControlAllowOrigin.headerkey) + " should not be *",FindingSeverity.HIGH, AccessControlAllowOriginDirective.NULL, None)]
        return []

