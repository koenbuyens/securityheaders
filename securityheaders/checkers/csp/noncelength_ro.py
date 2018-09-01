from .checkerro import CSPReportOnlyChecker
from .cspcheck_noncelength import CSPCheckNonceLength

class CSPReportOnlyNonceLengthChecker(CSPReportOnlyChecker):
    def check(self, headers, opt_options=dict()):
        csp = self.getcsp(headers)
        if not csp:
            return []
        return CSPCheckNonceLength(csp,self.applyCheckFunktionToDirectives).check(opt_options)
