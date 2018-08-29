#checks whether object-src or base-uri or default-src or ... is missing
# The default-src directive should be set as a fall-back when restrictions have not been specified.
from securityheaders.models.csp import CSP, CSPKeyword
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPMissingDirectiveChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp:
            return []

        findings = []

        directivesCausingXss = CSP.DIRECTIVES_CAUSING_XSS
        if csp.parsedstring and CSP.directive.DEFAULT_SRC in csp.parsedstring:
            defaultSrcValues = csp[CSP.directive.DEFAULT_SRC]
            if not CSP.directive.OBJECT_SRC in csp.parsedstring and (not CSPKeyword.NONE in defaultSrcValues or not str(CSPKeyword.NONE) in defaultSrcValues):
                findings.append(Finding(csp.headerkey, FindingType.MISSING_DIRECTIVES, 'Can you restrict object-src to \'none\'?',FindingSeverity.HIGH_MAYBE, CSP.directive.OBJECT_SRC))
            if CSP.directive.BASE_URI in csp.parsedstring:
                return findings
            else:
                directivesCausingXss = [CSP.directive.BASE_URI]
        else:
            findings.append(Finding(csp.headerkey, FindingType.MISSING_DIRECTIVES,"The default-src directive should be set as a fall-back when other restrictions have not been specified. ",FindingSeverity.HIGH,CSP.directive.DEFAULT_SRC))            

        for directive in directivesCausingXss:
            if not csp.parsedstring or not directive in csp.parsedstring:
                description = directive.value + ' directive is missing.'
                if directive == CSP.directive.OBJECT_SRC:
                    description = 'Missing object-src allows the injection of plugins which can execute JavaScript. Can you set it to \'none\'?'
                elif directive == CSP.directive.BASE_URI:
                    if not csp.policyHasScriptNonces() and not csp.policyHasScriptHashes() and csp.policyHasStrictDynamic():
                        continue
                    description = 'Missing base-uri allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. Can you set it to \'none\' or \'self\'?'
                findings.append(Finding(csp.headerkey, FindingType.MISSING_DIRECTIVES,description,FindingSeverity.HIGH,directive))
        
        return findings 

