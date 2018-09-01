from .checker import CSPChecker
from .cspcheck_unsafeeval import CSPCheckUnsafeEval

class CSPUnsafeEvalChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers)
        if not csp:
            return []
        directive = csp.directive.SCRIPT_SRC
        values = self.effectiveDirectiveValues(headers,directive, opt_options)
        return CSPCheckUnsafeEval(csp,directive, values).check()
