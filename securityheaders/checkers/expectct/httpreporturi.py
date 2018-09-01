from securityheaders.checkers import Finding, FindingType, FindingSeverity

from .checker import ExpectCTChecker

class ExpectCTHTTPReportURIChecker(ExpectCTChecker):
    
    def check(self, headers, opt_options=dict()):
        findings = []
        expectct = self.getexpectct(headers)
        
        if not expectct:
            return findings
        
        findings = []
        if expectct.reporturi() and expectct.reporturi().startswith('http://'):
            findings.append(Finding(expectct.headerkey,FindingType.SRC_HTTP,expectct.headerkey + 'communicates its reports via an insecure channel.', FindingSeverity.LOW, expectct.reporturi()))
        return findings
