from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckFlash(CSPCheck):
    def __init__(self, csp):
        self.csp = csp
    
    def check(self, opt_options=dict()):
        csp = self.csp
        if not csp:
            return []
        
        findings = []
        angular = []
        jsonp = []
        jsonpeval = []
        if 'bypasses' not in opt_options.keys():
            bypasses = []
        else:
            bypasses = opt_options['bypasses']
        
        directive = csp.getEffectiveDirective(csp.directive.OBJECT_SRC)
        objectSrcValues = []
        try:
            objectSrcValues = csp[directive]
        except KeyError:
            objectSrcValues = []
        if csp.directive.PLUGIN_TYPES in csp.parsedstring:
            pluginTypes = csp[csp.directive.PLUGIN_TYPES]
        else:
            pluginTypes = None

        if pluginTypes and not 'application/x-shockwave-flash' in pluginTypes:
            return []
        
        for value in objectSrcValues:
            if value == csp.keyword.NONE:
                return []
            
            url = '//' + Util.getSchemeFreeUrl(value)
            flashBypass = Util.matchWildcardUrls(url, bypasses)
            if (flashBypass):
                findings.append(Finding(csp.headerkey, FindingType.OBJECT_WHITELIST_BYPASS, flashBypass.netloc + ' is known to host Flash files which allow to bypass this CSP.',FindingSeverity.HIGH, directive, value))
            elif (directive == csp.directive.OBJECT_SRC):
                findings.append(Finding(csp.headerkey, FindingType.OBJECT_WHITELIST_BYPASS, 'Can you restrict object-src to \'none\' only?',FindingSeverity.MEDIUM_MAYBE, directive,value))

        return findings
