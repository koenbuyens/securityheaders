from .checker import CSPChecker
from .cspcheck_frameancestors import CSPCheckFrameAncestors

class CSPFrameAncestorsChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        return CSPCheckFrameAncestors(self.getcsp(headers), self.applyCheckFunktionToDirectives).check()
