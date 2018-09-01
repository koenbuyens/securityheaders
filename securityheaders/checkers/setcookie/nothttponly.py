from securityheaders.models.setcookie import SetCookie
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders.checkers.setcookie import SetCookieChecker
from .requiressecurity import requires_security

class CookieNotHttpOnlyChecker(SetCookieChecker):
    def check(self, headers, opt_options=dict()): 
        cookie = self.getcookie(headers)

        if not cookie:
            return []
	
        if not cookie.httponly() and requires_security(cookie):
            return [Finding(SetCookie.headerkey, FindingType.INSECURE_HEADER, 'The cookie does not have the httponly flag set.', FindingSeverity.MEDIUM,SetCookie.directive.HTTPONLY, None)]
        return []



