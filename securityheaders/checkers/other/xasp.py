from securityheaders.checkers import InfoDisclosureChecker

from securityheaders.models import XAspnetVersion, XAspnetMvcVersion

class XASPNetPresentChecker(InfoDisclosureChecker):
    def check(self, headers, opt_options=dict()):
        result = InfoDisclosureChecker.mycheck(self, XAspnetVersion.headerkey,headers, opt_options)
        result.extend(InfoDisclosureChecker.mycheck(self,XAspnetMvcVersion.headerkey,headers, opt_options))
        return result
