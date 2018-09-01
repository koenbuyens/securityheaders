from .checkerro import CSPReportOnlyChecker
from .cspcheck_missingdirective import CSPCheckMissingDirective

class CSPReportOnlyMissingDirectiveChecker(CSPReportOnlyChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp:
            return []
        return CSPCheckMissingDirective(csp,self.applyCheckFunktionToDirectives).check()

