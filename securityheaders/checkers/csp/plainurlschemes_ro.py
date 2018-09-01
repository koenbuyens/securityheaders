from .checkerro import CSPReportOnlyChecker
from .cspcheck_plainurlschemes import CSPCheckPlainUrlSchemes

class CSPReportOnlyPlainUrlSchemesChecker(CSPReportOnlyChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers)
        if not csp:
            return []
        values = csp.getEffectiveDirectives(csp.DIRECTIVES_CAUSING_XSS)
        return CSPCheckPlainUrlSchemes(csp,values).check()
