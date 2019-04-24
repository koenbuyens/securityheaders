from securityheaders.models import Directive

class ReferrerPolicyDirective(Directive):
    NO_REFERRER = 'no-referrer'
    NO_REFERRER_WHEN_DOWNGRADE = 'no-referrer-when-downgrade'
    ORIGIN = 'origin'
    ORIGIN_WHEN_CROSS_ORIGIN = 'origin-when-cross-origin'
    SAME_ORIGIN = 'same-origin'
    STRICT_ORIGIN = 'strict-origin'
    STRICT_ORIGIN_WHEN_CROSS_ORIGIN = 'strict-origin-when-cross-origin'
    UNSAFE_URL = 'unsafe-url'

    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, ReferrerPolicyDirective):
            return True
        return any(directive.lower() == item for item in cls)

    @classmethod
    def directiveseperator(cls):
        return ','

    @classmethod
    def directivevalueseperator(cls):
        return None
