from .checkerro import CSPReportOnlyChecker
from .cspcheck_framesrc import CSPCheckFrameSrc

class CSPReportOnlyFrameSrcChecker(CSPReportOnlyChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        return CSPCheckFrameSrc(self.getcsp(headers), self.applyCheckFunktionToDirectives).check()
