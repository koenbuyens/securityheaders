from securityheaders.models.hsts import HSTS
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders.checkers.hsts import HSTSChecker

class HSTSMaxAgeZeroChecker(HSTSChecker):
    def check(self, headers, opt_options=dict()): 
        findings = []
        hsts = self.gethsts(headers) 

        if not hsts:
            return findings
        if hsts.maxAge() == 0:
            return [Finding(HSTS.headerkey, FindingType.MAX_AGE_ZERO, str(HSTS.headerkey) + ' is disabled due to max age equal to zero.', FindingSeverity.LOW, HSTS.directive.MAX_AGE)]

        return findings

