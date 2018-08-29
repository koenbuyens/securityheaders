from securityheaders.checkers import Checker
from securityheaders.models.featurepolicy import FeaturePolicy, FeaturePolicyDirective

class FeaturePolicyChecker(Checker):

    def getfeaturepolicy(self, headers):
        return self.extractheader(headers, FeaturePolicy) 

    def effectiveDirectiveValues(self, headers, actualdirective):
        policy = self.geatfeaturepolicy(headers)
        if not policy:
            return []
        return policy.getEffectiveValues(actualdirective)

    def applyCheckFunktionToDirectives(self, parsedPolicy, check, findings, opt_directives=[]):
        directiveNames = []
        if parsedPolicy:
            directiveNames =parsedPolicy.keys()
        if opt_directives:
            directiveNames = opt_directives
        for directive in directiveNames:
            directiveValues = parsedPolicy[directive]
            if directiveValues:
                check(directive, directiveValues, findings)       
