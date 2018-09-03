from securityheaders.models.cors import AccessControlExposeHeadersDirective, AccessControlExposeHeaders
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from .checker import AccessControlExposeHeadersChecker

class AccessControlExposeHeadersSensitiveChecker(AccessControlExposeHeadersChecker):
    def check(self, headers, opt_options=dict()):
        headers = self.getexposeheaders(headers)
        if not headers:
            return []

        result = []
        for header in headers.headers():
            if self.__issensitive__(header):
                result.append(Finding(AccessControlExposeHeaders.headerkey, FindingType.SENSITIVE_HEADER_EXPOSED, str(AccessControlExposeHeaders.headerkey) +  " exposes sensitive headers to JavaScript. An attacker can deceive the victim into browsing to an untrusted origin containing JavaScript that makes an HTTP request to the target origin. The malicious JavaScript code reads the value of the sensitive header and shares it with the attacker. If the header contains session information, the attacker can hijack the victim's session.",FindingSeverity.MEDIUM, str(header),None))
        return result

    def __issensitive__(self, header):
       if 'session' in header:
           return True
       if 'authentication' in header:
           return True
       if 'authorization' in header:
           return True
       if 'token' in header:
           return True
       return False
