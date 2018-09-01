from .checker import CSPChecker
from .cspcheck_unsafeinline import CSPCheckUnsafeInline

class CSPUnsafeInlineChecker(CSPChecker):
    def check(self, headers, opt_options=dict()):
        csp = self.getcsp(headers)
        if not csp:
            return []
        directive = csp.directive.SCRIPT_SRC
        values = self.effectiveDirectiveValues(headers,directive, opt_options)
        return CSPCheckUnsafeInline(csp,directive, values).check()

