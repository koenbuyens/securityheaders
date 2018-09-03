from securityheaders.models.cors import AccessControlAllowOriginDirective, AccessControlAllowOrigin
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from .checker import AccessControlAllowOriginChecker

class AccessControlAllowOriginStarChecker(AccessControlAllowOriginChecker):
    def check(self, headers, opt_options=dict()):
        origins = self.getorigins(headers)
        if origins and origins.isstar():
            return [Finding(AccessControlAllowOrigin.headerkey, FindingType.STAR_ORIGIN, str(AccessControlAllowOrigin.headerkey) + " should not be *",FindingSeverity.HIGH, AccessControlAllowOriginDirective.STAR, None)]
        return []
