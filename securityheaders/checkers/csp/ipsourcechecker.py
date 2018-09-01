from .checker import CSPChecker
from .cspcheck_ipsource import CSPCheckIPSource

class CSPIPSourceChecker(CSPChecker):
    def check(self, headers, opt_options=dict()):
        csp = self.getcsp(headers)
        if not csp:
            return []
        return CSPCheckIPSource(csp,self.applyCheckFunktionToDirectives).check()
