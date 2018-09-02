from .checkerro import CSPReportOnlyChecker
from .cspcheck_frameancestors import CSPCheckFrameAncestors

class CSPReportOnlyFrameAncestorsChecker(CSPReportOnlyChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        return CSPCheckFrameAncestors(self.getcsp(headers), self.applyCheckFunktionToDirectives).check()
