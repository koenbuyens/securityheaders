from .checker import CSPChecker
from .checkerro import CSPReportOnlyChecker
from securityheaders.checkers import Finding,FindingType,FindingSeverity

class CSPReportOnlyNoCSPChecker(CSPReportOnlyChecker, CSPChecker):
    def check(self, headers, opt_options=dict()):
        rocsp = CSPReportOnlyChecker.getcsp(self,headers)
        csp = CSPChecker.getcsp(self,headers)

        if not csp and rocsp:
            description = "The CSP is not enforced as only the content-security-policy-report-only header is present. Can you set the content-security-policy?"
            return [Finding(rocsp.headerkey, FindingType.REPORT_ONLY,description,FindingSeverity.INFO, None, None)]
        return []
