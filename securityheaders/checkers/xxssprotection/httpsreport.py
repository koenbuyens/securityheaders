from securityheaders.models.xxssprotection import XXSSProtectionDirective, XXSSProtection
from securityheaders.checkers import FindingSeverity, FindingType, Finding
from securityheaders.checkers.xxssprotection import XXSSProtectionChecker


class XXSSProtectionHTTPSReportChecker(XXSSProtectionChecker):
    def check(self, headers, opt_options=dict()):
        xxss = self.getxxss(headers)
        
        if xxss and xxss.report() and xxss.report().startswith('http:'):
            return [Finding(XXSSProtection.headerkey, FindingType.HTTP_REPORT,'This header sets the configuration for the cross-site scripting filter built into most browsers. Violations should be reported to an HTTPS endpoint".',FindingSeverity.LOW, XXSSProtectionDirective.REPORT, xxss.report())  ]          
        return []
