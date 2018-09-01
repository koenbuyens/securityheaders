from .checkerro import CSPReportOnlyChecker
from .cspcheck_ipsource import CSPCheckIPSource

class CSPReportOnlyIPSourceChecker(CSPReportOnlyChecker):
    def check(self, headers, opt_options=dict()):
        csp = self.getcsp(headers)
        if not csp:
            return []
        return CSPCheckIPSource(csp,self.applyCheckFunktionToDirectives).check()
