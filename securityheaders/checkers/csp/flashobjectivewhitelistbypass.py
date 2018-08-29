from securityheaders import Util
from securityheaders.models.csp import CSP, CSPKeyword
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPFlashObjectWhitelistBypassChecker(CSPChecker):

    def myoptions(cls):
        return {'bypasses':list}

    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp or not csp.parsedstring:
            return []

        findings = []
        me = self.__class__.__name__

        if me not in opt_options.keys() or 'bypasses' not in opt_options[me].keys():
            bypasses = []
        else:
            bypasses = opt_options[me]['bypasses']

        directive = csp.getEffectiveDirective(CSP.directive.OBJECT_SRC)
        objectSrcValues = []
        try:
            objectSrcValues = csp[directive]
        except KeyError:
            objectSrcValues = []
        if CSP.directive.PLUGIN_TYPES in csp.parsedstring:
            pluginTypes = csp[CSP.directive.PLUGIN_TYPES]
        else:
            pluginTypes = None

        if pluginTypes and not 'application/x-shockwave-flash' in pluginTypes:
            return []

        for value in objectSrcValues:
            if value == CSPKeyword.NONE:
                return []

            url = '//' + Util.getSchemeFreeUrl(value)
            flashBypass = Util.matchWildcardUrls(url, bypasses)
            if (flashBypass):
                findings.append(Finding(CSP.headerkey, FindingType.OBJECT_WHITELIST_BYPASS, flashBypass.netloc + ' is known to host Flash files which allow to bypass this CSP.',FindingSeverity.HIGH, directive, value))
            elif (directive == CSP.directive.OBJECT_SRC):
                findings.append(Finding(CSP.headerkey, FindingType.OBJECT_WHITELIST_BYPASS, 'Can you restrict object-src to \'none\' only?',FindingSeverity.MEDIUM_MAYBE, directive,value))

        return findings
