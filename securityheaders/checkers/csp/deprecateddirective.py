#checks whether csp of v3 contains report-uri
from .checker import CSPChecker
from .cspcheck_deprecated import CSPCheckDeprecated

class CSPDeprecatedDirectiveChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        return CSPCheckDeprecated(self.getcsp(headers)).check()
