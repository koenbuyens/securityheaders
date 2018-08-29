from securityheaders.models.xxssprotection import XXSSProtectionDirective, XXSSProtection
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders.checkers.xxssprotection import XXSSProtectionChecker

class XXSSProtectionBlockChecker(XXSSProtectionChecker):
    def check(self, headers, opt_options=dict()):
        xxss = self.getxxss(headers)
        if xxss and not xxss.one():
            return [Finding(XXSSProtection.headerkey, FindingType.DISABLE_XSS_FILTER,'This header sets the configuration for the cross-site scripting filter built into most browsers. The recommended value is "X-XSS-Protection: 1; mode=block".',FindingSeverity.LOW, XXSSProtectionDirective.ONE,XXSSProtectionDirective.ZERO)]
        return []
