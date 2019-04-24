from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders.models import ReferrerPolicy
from securityheaders.checkers.referrerpolicy import ReferrerPolicyChecker


class ReferrerPolicyInsecureChecker(ReferrerPolicyChecker):
    def check(self, headers, opt_options=dict()):
        findings = []
        policy = self.getreferrerpolicy(headers) 

        if not policy:
            return findings
        if policy.unsafe_url():
            findings.append(Finding(ReferrerPolicy.headerkey, FindingType.UNSAFE_URL, 'If this policy is set, it should not use unsafe-url and origin-when-cross-origin as it can transfer sensitive information (via the Referer header) from HTTPS environments to HTTP environments.', FindingSeverity.LOW, ReferrerPolicy.directive.UNSAFE_URL))
        if policy.origin_when_cross_origin():
            findings.append(Finding(ReferrerPolicy.headerkey, FindingType.ORIGIN_WHEN_CROSS_ORIGIN, 'If this policy is set, it should not use unsafe-url and origin-when-cross-origin as it can transfer sensitive information (via the Referer header) from HTTPS environments to HTTP environments.', FindingSeverity.LOW, ReferrerPolicy.directive.ORIGIN_WHEN_CROSS_ORIGIN))
        return findings
