from securityheaders.models import SecurityHeader
from securityheaders.models.featurepolicy import FeaturePolicyDirective, FeaturePolicyKeyword
from securityheaders.models.annotations import *
import copy

@requiredheader
@description('It is a new header that allows a site to control which features and APIs can be used in the browser.')
@headername('feature-policy')
@headerref('https://wicg.github.io/feature-policy/')
class FeaturePolicy(SecurityHeader):
    directive = FeaturePolicyDirective

    def __init__(self, unparsedstring):
       SecurityHeader.__init__(self, unparsedstring, FeaturePolicyDirective, FeaturePolicyKeyword)

    def geturls(self, directives=None):
        directiveNames = []
        result = []
        if self.parsedstring:
            directiveNames = self.keys()
        if directives:
            directiveNames = directives
        for directive in directiveNames:
            directiveValues = self.parsedstring[directive]
            for directiveValue in directiveValues:
                directiveValue = str(directiveValue)
                if not FeaturePolicyKeyword.isKeyword(directiveValue) and not FeaturePolicyKeyword.isValue(directiveValue):
                    result.append(directiveValue)
        return result 

    def getEffectiveDirectives(self):
        return self.getEffectiveFeaturePolicy().getdirectives()


    def getEffectiveFeaturePolicy(self):
        """ returns the effective policy for a given version; i.e. removes keywords/directives that are not relevant
        """
        effectivePolicy = FeaturePolicy(None)
        effectivePolicy.parsedstring = copy.deepcopy(self.parsedstring)

        for directive in FeaturePolicyDirective:
            if directive not in effectivePolicy.keys():
                effectivePolicy.parsedstring[directive] = [directive.getDefaultValue()]

        return effectivePolicy


    def getEffectiveValues(self, directive):
        try:
            if isinstance(directive, str):
                directive = FeaturePolicyDirective[directive]
            return self.getEffectiveFeaturePolicy()[directive]
        except Exception:
            return []
