from .checkerro import CSPReportOnlyChecker
from .cspcheck_wildcard import CSPCheckWildCard

class CSPReportOnlyWildCardChecker(CSPReportOnlyChecker):
    def check(self, headers, opt_options=dict()): 
        return CSPCheckWildCard(self.getcsp(headers)).check()
