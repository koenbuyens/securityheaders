from .checker import CSPChecker
from .cspcheck_plainurlschemes import CSPCheckPlainUrlSchemes

class CSPPlainUrlSchemesChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers)
        if not csp:
            return []
        values = csp.getEffectiveDirectives(csp.DIRECTIVES_CAUSING_XSS)
        return CSPCheckPlainUrlSchemes(csp,values).check()
