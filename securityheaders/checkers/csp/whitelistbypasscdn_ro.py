from .checkerro import CSPReportOnlyChecker
from .cspcheck_whitelistcdn import CSPCheckWhitelistCDN

class CSPReportOnlyScriptWhitelistCDNBypassChecker(CSPReportOnlyChecker):
    def myoptions(cls):
        return {'cdn':list}
    
    def check(self, headers, opt_options=dict()):
        me = self.__class__.__name__
        if me in opt_options.keys():
            options = opt_options[me]
        else:
            options = {}
        return CSPCheckWhitelistCDN(self.getcsp(headers)).check(options)
