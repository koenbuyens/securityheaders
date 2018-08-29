from securityheaders.checkers import Checker
from securityheaders.models.csp import CSP, CSPDirective, CSPVersion

class CSPChecker(Checker):

    def myoptions(cls):
        return {'CSPversion':CSPVersion}

    def getcsp(self, headers):
        return self.extractheader(headers, CSP) 


    def extractEffectiveCSP(self, headers, opt_options=[]):
        csp = self.getcsp(headers) 
        me = self.__class__.__name__
        if not csp:
            return None
        if me in opt_options.keys() and 'CSPversion' in opt_options[me].keys():
            version = opt_options[me]['CSPversion']
        else:
            version = CSPVersion.CSP3
        return csp.getEffectiveCsp(version)


    def extractEffectiveDirective(self, headers, directive, options):
        csp = self.extractEffectiveCSP(headers, options)
        if not csp:
            return None
        return csp.getEffectiveDirective(CSPDirective.SCRIPT_SRC)



    def effectiveDirectiveValues(self, headers, actualdirective, options):
        csp = self.extractEffectiveCSP(headers, options)
        if not csp:
            return []
        directive = csp.getEffectiveDirective(actualdirective)       
        if not directive:
            return []

        values = []
        try:
            values = csp[directive]
        except:
            values = []
        return values


    def applyCheckFunktionToDirectives(self, parsedCsp, check, findings, opt_directives=[]):
        directiveNames = []
        if parsedCsp:
            directiveNames = parsedCsp.keys()
        if opt_directives:
            directiveNames = opt_directives
        for directive in directiveNames:
            directiveValues = parsedCsp[directive]
            if directiveValues:
                check(directive, directiveValues, findings)       
