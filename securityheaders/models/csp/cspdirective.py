from securityheaders.models import Directive
from securityheaders.models.annotations import requireddirectives, requireddirectivevalues

@requireddirectivevalues('form-action','frame-ancestors','report-uri','report-to','require-sri-for','plugin-types','worker-src','style-src','object-src','manifest-src','frame-src','default-src','connect-src','child-src')
class CSPDirective(Directive):
# Fetch directives
    CHILD_SRC = 'child-src', 'childSrc'
    CONNECT_SRC = 'connect-src', 'connectSrc'
    DEFAULT_SRC = 'default-src', 'defaultSrc'
    FONT_SRC = 'font-src', 'fontSrc'
    FRAME_SRC = 'frame-src', 'frameSrc'
    IMG_SRC = 'img-src', 'imgSrc'
    MEDIA_SRC = 'media-src', 'mediaSrc'
    OBJECT_SRC = 'object-src', 'objectSrc'
    SCRIPT_SRC = 'script-src', 'scriptSrc'
    STYLE_SRC = 'style-src', 'styleSrc'

    MANIFEST_SRC = 'manifest-src', 'manifestSrc'
    WORKER_SRC = 'worker-src', 'workerSrc'

# Document directives
    BASE_URI = 'base-uri','baseUri'
    PLUGIN_TYPES = 'plugin-types','pluginTypes'
    SANDBOX = 'sandbox','sandBox'
    DISOWN_OPENER = 'disown-opener','disownOpener'

# Navigation directives
    FORM_ACTION = 'form-action','formAction'
    FRAME_ANCESTORS = 'frame-ancestors','frameAncestors'

# Reporting directives
    REPORT_TO = 'report-to','reportTo'
    REPORT_URI = 'report-uri','reportUri'

# Other directives
    BLOCK_ALL_MIXED_CONTENT = 'block-all-mixed-content','blockAllMixedContent'
    UPGRADE_INSECURE_REQUESTS = 'upgrade-insecure-requests','upgradeInsecureRequests'
    REFLECTED_XSS = 'reflected-xss','reflectedXss'
    REFERRER = 'referrer'
    REQUIRE_SRI_FOR = 'require-sri-for','requireSriFor'


    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, CSPDirective):
            return True
        return any(directive.lower() == item for item in list(cls.keys()))
