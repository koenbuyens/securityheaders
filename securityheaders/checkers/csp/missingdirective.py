from .checker import CSPChecker
from .cspcheck_missingdirective import CSPCheckMissingDirective

class CSPMissingDirectiveChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp:
            return []
        return CSPCheckMissingDirective(csp,self.applyCheckFunktionToDirectives).check()

