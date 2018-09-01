from .checker import CSPChecker
from .cspcheck_wildcard import CSPCheckWildCard


class CSPWildCardChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        return CSPCheckWildCard(self.getcsp(headers)).check()
