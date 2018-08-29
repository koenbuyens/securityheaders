from securityheaders.models.hsts import HSTS
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders.checkers.hsts import HSTSChecker

class HSTSSubdomainsChecker(HSTSChecker):
    def check(self, headers, opt_options=dict()): 
        findings = []
        hsts = self.gethsts(headers) 

        if not hsts:
            return findings
        if not hsts.includesubdomains():
            return [Finding(HSTS.headerkey, FindingType.NO_SUBDOMAINS, 'include subdomains was not specified.', FindingSeverity.LOW, HSTS.directive.INCLUDESUBDOMAINS)]

        return findings
