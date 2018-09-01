from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckMissingDirective(CSPCheck):
    
    def __init__(self, csp, function):
        self.csp = csp
    
    def check(self):
        csp = self.csp
        if not csp:
            return []
                
        findings = []
     
        directivesCausingXss = csp.DIRECTIVES_CAUSING_XSS
        if csp.parsedstring and csp.directive.DEFAULT_SRC in csp.parsedstring:
            defaultSrcValues = csp[csp.directive.DEFAULT_SRC]
            if not csp.directive.OBJECT_SRC in csp.parsedstring and (not csp.keyword.NONE in defaultSrcValues or not str(csp.keyword.NONE) in defaultSrcValues):
                findings.append(Finding(csp.headerkey, FindingType.MISSING_DIRECTIVES, 'Can you restrict object-src to \'none\'?',FindingSeverity.HIGH_MAYBE, csp.directive.OBJECT_SRC))
            if csp.directive.BASE_URI in csp.parsedstring:
                return findings
            else:
                directivesCausingXss = [csp.directive.BASE_URI]
        else:
            findings.append(Finding(csp.headerkey, FindingType.MISSING_DIRECTIVES,"The default-src directive should be set as a fall-back when other restrictions have not been specified. ",FindingSeverity.HIGH,csp.directive.DEFAULT_SRC))
        
        for directive in directivesCausingXss:
            if not csp.parsedstring or not directive in csp.parsedstring:
                description = directive.value + ' directive is missing.'
                if directive == csp.directive.OBJECT_SRC:
                    description = 'Missing object-src allows the injection of plugins which can execute JavaScript. Can you set it to \'none\'?'
                elif directive == csp.directive.BASE_URI:
                    if not csp.policyHasScriptNonces() and not csp.policyHasScriptHashes() and csp.policyHasStrictDynamic():
                        continue
                    description = 'Missing base-uri allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. Can you set it to \'none\' or \'self\'?'
                findings.append(Finding(csp.headerkey, FindingType.MISSING_DIRECTIVES,description,FindingSeverity.HIGH,directive))

        return findings
