from securityheaders.checkers.csp import CSPChecker
from securityheaders.models.csp import CSPReportOnly, CSPDirective, CSPVersion

class CSPReportOnlyChecker(CSPChecker):

    def getcsp(self, headers):
        return self.extractheader(headers, CSPReportOnly)
