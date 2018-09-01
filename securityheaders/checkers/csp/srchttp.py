from .checker import CSPChecker
from .cspcheck_srchttp import CSPCheckSrcHttp

class CSPSCRHTTPChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        return CSPCheckSrcHttp(self.getcsp(headers), self.applyCheckFunktionToDirectives).check()
