#checks whether * has been used
from securityheaders import Util
from securityheaders.models.featurepolicy import FeaturePolicy, FeaturePolicyKeyword, FeaturePolicyDirective
from securityheaders.checkers import Finding, FindingType, FindingSeverity

from .checker import FeaturePolicyChecker

class FeaturePolicyWildCardChecker(FeaturePolicyChecker):
    def check(self, headers, opt_options=dict()): 
        policy = self.getfeaturepolicy(headers) 
        if not policy or not policy.parsedstring:
            return []

        findings = []

        directivesToCheck = policy.getEffectiveDirectives()

        for directive in directivesToCheck:
            values = policy.getEffectiveValues(directive)
            
            for value in values:
                url = Util.getSchemeFreeUrl(value)
                if url and str(FeaturePolicyKeyword.STAR) in url and len(url) == 1 and directive != FeaturePolicyDirective.PICTURE_IN_PICTURE:
                    findings.append(Finding(policy.headerkey, FindingType.PLAIN_WILDCARD, directive.value + ' should not allow \'*\' as source. It enables the current page and nesting contexts, such as iframes, to use the feature. It may be better to disable and explicitly tell the iframe which feature is allowed.',FindingSeverity.LOW, directive, value))

        return findings

