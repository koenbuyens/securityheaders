#checks whether csp of v3 contains report-uri
from securityheaders.models.csp import CSP
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPDeprecatedDirectiveChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp or not csp.parsedstring:
            return []

        findings = []

        if CSP.directive.REPORT_URI in csp.parsedstring:
            findings.append(Finding(CSP.headerkey,FindingType.DEPRECATED_DIRECTIVE,'report-uri is deprecated in CSP3. Please use the report-to directive instead.', FindingSeverity.INFO, CSP.directive.REPORT_URI))
        return findings

