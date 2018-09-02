from .checker import CSPChecker
from .cspcheck_framesrc import CSPCheckFrameSrc

class CSPFrameSrcChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        return CSPCheckFrameSrc(self.getcsp(headers), self.applyCheckFunktionToDirectives).check()
