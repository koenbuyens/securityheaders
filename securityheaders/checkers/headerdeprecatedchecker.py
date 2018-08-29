from securityheaders.checkers import Checker, FindingType, Finding, FindingSeverity

class HeaderDeprecatedChecker(Checker):

    def mycheck(self, headers, header):
        if not header or not headers:
           return []

        if header in headers.keys() or header.lower() in headers.keys():
            value = headers[header] if header in headers.keys() else headers[header.lower()]
            return [Finding(header, FindingType.DEPRECATED_HEADER, header + ' header present. This header is deprecated and should not be used.',FindingSeverity.INFO, None, value)]
        return []  
