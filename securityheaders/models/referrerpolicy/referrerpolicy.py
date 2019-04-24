from securityheaders.models import SecurityHeader
from securityheaders.models.referrerpolicy import ReferrerPolicyDirective
from securityheaders.models.annotations import *

@requiredheader
@description('It is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites.')
@headername('referrer-policy')
@headerref('https://www.w3.org/TR/referrer-policy/')
class ReferrerPolicy(SecurityHeader):
    directive = ReferrerPolicyDirective

    def __init__(self, unparsedstring):
        SecurityHeader.__init__(self, unparsedstring, ReferrerPolicyDirective)

    def no_referrer(self):
        try:
            return ReferrerPolicyDirective.NO_REFERRER in self.parsedstring
        except:
            return False

    def no_referrer_when_downgrade(self):
        try:
            return ReferrerPolicyDirective.NO_REFERRER_WHEN_DOWNGRADE in self.parsedstring
        except:
            return False

    def origin(self):
        try:
            return ReferrerPolicyDirective.ORIGIN in self.parsedstring
        except:
            return False

    def origin_when_cross_origin(self):
        try:
            return ReferrerPolicyDirective.ORIGIN_WHEN_CROSS_ORIGIN in self.parsedstring
        except:
            return False

    def same_origin(self):
        try:
            return ReferrerPolicyDirective.SAME_ORIGIN in self.parsedstring
        except:
            return False

    def strict_origin(self):
        try:
            return ReferrerPolicyDirective.STRICT_ORIGIN in self.parsedstring
        except:
            return False

    def strict_origin_when_cross_origin(self):
        try:
            return ReferrerPolicyDirective.STRICT_ORIGIN_WHEN_CROSS_ORIGIN in self.parsedstring
        except:
            return False

    def unsafe_url(self):
        try:
            return ReferrerPolicyDirective.UNSAFE_URL in self.parsedstring
        except:
            return False
