#checks whether csp of v3 contains report-uri
from .checkerro import CSPReportOnlyChecker
from .cspcheck_deprecated import CSPCheckDeprecated

class CSPReportOnlyDeprecatedDirectiveChecker(CSPReportOnlyChecker):
    def check(self, headers, opt_options=dict()): 
        return CSPCheckDeprecated(self.getcsp(headers)).check()
