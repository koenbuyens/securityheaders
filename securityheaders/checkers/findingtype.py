from enum import Enum

class FindingType(Enum):
    #INFO
    INFO_HEADER = 1 #used for collecting raw headers
    INFO_DIRECTIVE = 2 #used for recording directive info
    INFO_URL = 3

    #syntax issues
    MISSING_SEMICOLON = 100
    UNKNOWN_DIRECTIVE = 101
    INVALID_KEYWORD = 102
    IGNORED = 405
    DEPRECATED_DIRECTIVE = 309
    MISSING_DIRECTIVES = 300
    MISSING_VALUES = 299


    #generic issues
    MISSING_HEADER = 103
    INSECURE_HEADER = 104
    INFO_DISCLOSURE = 105
    DEPRECATED_HEADER = 106
    INCONSISTENCIES = 107

    SRC_HTTP = 310

    #CSP-specific issues
    SCRIPT_UNSAFE_INLINE = 301
    SCRIPT_UNSAFE_EVAL = 302
    PLAIN_URL_SCHEMES = 303
    PLAIN_WILDCARD = 304
    SCRIPT_WHITELIST_BYPASS = 305
    OBJECT_WHITELIST_BYPASS = 306
    NONCE_LENGTH = 307
    IP_SOURCE = 308


    STRICT_DYNAMIC = 400
    STRICT_DYNAMIC_NOT_STANDALONE = 401
    NONCE_HASH = 402
    UNSAFE_INLINE_FALLBACK = 403
    WHITELIST_FALLBACK = 404
    
    REPORT_ONLY=410

    #CORS issues
    STAR_ORIGIN = 500
    NULL_ORIGIN = 501
    HTTP_ORIGIN = 502
    MAX_AGE_TOO_LONG = 503
    SENSITIVE_HEADER_EXPOSED = 504

    #XXSSProtection
    DISABLE_XSS_FILTER = 600
    HTTP_REPORT = 601
    

    ALLOW_FROM_EMPTY = 700
    ALLOW_FROM = 701

    #HSTS
    NO_SUBDOMAINS = 800
    MAX_AGE_ZERO = 801

    NOSNIFF = 900

    #REFERRERPOLICY
    UNSAFE_URL=950
    ORIGIN_WHEN_CROSS_ORIGIN=951

    #EXPECT_CT
    NOT_ENFORCED = 970

    #ERROR
    ERROR = 1000

    def __str__(self):
        """ Returns a string representaiton of this finding type   
        """
        return str(self.name.lower())   
