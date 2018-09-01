from .checkerro import CSPReportOnlyChecker
from .cspcheck_srchttp import CSPCheckSrcHttp

class CSPReportOnlySCRHTTPChecker(CSPReportOnlyChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        return CSPCheckSrcHttp(self.getcsp(headers), self.applyCheckFunktionToDirectives).check()
