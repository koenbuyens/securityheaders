from .checker import CSPChecker
from .cspcheck_noncelength import CSPCheckNonceLength

class CSPNonceLengthChecker(CSPChecker):
    def check(self, headers, opt_options=dict()):
        csp = self.getcsp(headers)
        if not csp:
            return []
        return CSPCheckNonceLength(csp,self.applyCheckFunktionToDirectives).check()
