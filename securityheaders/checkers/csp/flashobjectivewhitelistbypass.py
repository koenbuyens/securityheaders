from .checker import CSPChecker
from .cspcheck_flash import CSPCheckFlash

class CSPFlashObjectWhitelistBypassChecker(CSPChecker):

    def myoptions(cls):
        return {'bypasses':list}

    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        me = self.__class__.__name__
        if me in opt_options.keys():
            options = opt_options[me]
        else:
            options = {}
        return CSPCheckFlash(self.getcsp(headers)).check(options)
