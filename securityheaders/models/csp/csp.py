import os.path
import re
import copy

from securityheaders.models import SecurityHeader
from securityheaders.models.csp import CSPDirective, CSPKeyword, CSPVersion
from securityheaders.models.annotations import *

@requiredheader
@description('This header protects against XSS attacks. By whitelisting sources of approved content, the browser does not load malicious assets.')
@headername('content-security-policy')
@headerref('http://www.w3.org/TR/CSP/')
class CSP(SecurityHeader):
    directive = CSPDirective
    keyword = CSPKeyword

    def __init__(self, unparsedstring):
       SecurityHeader.__init__(self, unparsedstring, CSPDirective, CSPKeyword)


    # See https://developer.mozilla.org/en-US/docs/Glossary/Fetch_directive
    FETCH_DIRECTIVES = [
        CSPDirective.CHILD_SRC,
        CSPDirective.CONNECT_SRC,
        CSPDirective.DEFAULT_SRC,
        CSPDirective.FONT_SRC,
        CSPDirective.FRAME_SRC,
        CSPDirective.IMG_SRC,
        CSPDirective.MANIFEST_SRC,
        CSPDirective.MEDIA_SRC,
        CSPDirective.OBJECT_SRC,
        CSPDirective.SCRIPT_SRC,
        CSPDirective.STYLE_SRC,
        CSPDirective.WORKER_SRC
    ]


    # these directives may cause XSS
    DIRECTIVES_CAUSING_XSS = [
        CSPDirective.SCRIPT_SRC,
        CSPDirective.OBJECT_SRC,
        CSPDirective.BASE_URI
    ]

    # These schemes may cause XSS
    URL_SCHEMES_CAUSING_XSS = [
        'data:', 
        'http:',
        'https:'
    ]


    def getEffectiveDirective(self, directive):
        """ returns the effective directive of a directive. Relevant for fetch directives which default to default-src when not specified

        Args:
            directive (CSPDirective): the directive for which we want to get the effective directive
        """
        # Only fetch directives default to default-src.
        if not directive or not self.parsedstring:
            return directive
        if not(directive in self.parsedstring) and directive in CSP.FETCH_DIRECTIVES:
            return CSPDirective.DEFAULT_SRC
        return directive

    def getEffectiveDirectives(self, directives):
        """ Uses the above function on a list of directives

        Args:
            directives (list): the list of directives for which we want to get the effective directives
        """
        effectiveDirectives = set()
        for directive in directives:
            effectiveDirectives.add(self.getEffectiveDirective(directive))
        return list(effectiveDirectives)

    def policyHasScriptNonces(self):
        """ Checks whether a CSP uses nonces in the script-src directive
        """
        directiveName = self.getEffectiveDirective(CSPDirective.SCRIPT_SRC)
        values = []
        try:
            values = self[directiveName]
        except:
            values = []
        for element in values:
            if(CSP.isNonce(element)):
                return True
        return False

    def policyHasScriptHashes(self):
        """ Checks whether a CSP uses hashes in the script-src directive
        """
        directiveName = self.getEffectiveDirective(CSPDirective.SCRIPT_SRC)
        values = []
        try:
            values = self[directiveName]
        except:
            values = []
        for element in values:
            if(CSP.isHash(element)):
                return True
        return False

    def policyHasStrictDynamic(self):
        """ Checks whether a CSP uses the strict-dynamic keyword in a script-src directive
        """
        directiveName = self.getEffectiveDirective(CSPDirective.SCRIPT_SRC)
        values = []
        try:
            values = self[directiveName]
        except:
            values = []
        return CSPKeyword.STRICT_DYNAMIC in values


    def getEffectiveCsp(self, cspVersion):
        """ returns the effective csp for a given version; i.e. removes keywords/directives that are not relevant

        Args:
            cspVersion (CSPVersion): the version for which we want to get the effective policy
        """
        effectiveCsp = CSP(None)
        effectiveCsp.parsedstring = copy.deepcopy(self.parsedstring)

        directive = self.getEffectiveDirective(CSPDirective.SCRIPT_SRC)
        values = []
        try:
            values = self[directive]
        except:
            values = []

        if not effectiveCsp.parsedstring:
            return effectiveCsp

        if (directive in effectiveCsp.parsedstring and (effectiveCsp.policyHasScriptNonces() or effectiveCsp.policyHasScriptHashes())):
            if cspVersion >= CSPVersion.CSP2:
            # Ignore 'unsafe-inline' in CSP >= v2, if a nonce or a hash is present.
                if CSPKeyword.UNSAFE_INLINE.value in values:
                    if CSPKeyword.UNSAFE_INLINE in effectiveCsp[directive]: 
                        effectiveCsp[directive].remove(CSPKeyword.UNSAFE_INLINE)
                    #findings.append(Finding(CSP.headerkey, FindingType.IGNORED,'unsafe-inline is ignored if a nonce or a hash is present. (CSP2 and above)', FindingSeverity.NONE, directive, CSPKeyword.UNSAFE_INLINE))
            else:
            # remove nonces and hashes (not supported in CSP < v2).
                for value in values:
                    if value.startswith("'nonce-") or value.startswith("'sha"):
                        effectiveCsp[directive].remove(value)


        if directive in effectiveCsp.parsedstring and self.policyHasStrictDynamic():
        # Ignore whitelist in CSP >= v3 in presence of 'strict-dynamic'.
            if cspVersion >= csp.Version.CSP3:
                for value in values:
                    if not value.startswith("'") or value == CSPKeyword.SELF or value == CSPKeyword.UNSAFE_INLINE.value:
                        if value in effectiveCsp[directive]:
                            effectiveCsp[directive].remove(value)
                        #findings.append(Finding(CSP.headerkey, FindingType.IGNORED, 'Because of strict-dynamic this entry is ignored in CSP3 and above',FindingSeverity.NONE, directive, value))
        else:
          # strict-dynamic not supported.
          try:
              effectiveCsp[directive].remove(CSPKeyword.STRICT_DYNAMIC)
          except:
              pass

        if cspVersion < CSPVersion.CSP3:
        # Remove CSP3 directives from pre-CSP3 policies.
            try:
                effectiveCsp[directive].remove(CSPDirective.REPORT_TO.value)
            except:
                pass
            try:
                effectiveCsp[directive].remove(CSPDirective.WORKER_SRC.value)
            except:
                pass
            try:
                effectiveCsp[directive].remove(CSPDirective.MANIFEST_SRC.value)
            except:
                pass

        return effectiveCsp

    def geturls(self, directives=None):
        directiveNames = []
        result = []
        if self.parsedstring:
            directiveNames = self.keys()
        if directives:
            directiveNames = directives
        for directive in directiveNames:
            directiveValues = self.parsedstring[directive]
            for directiveValue in directiveValues:
                directiveValue = str(directiveValue)
                if not CSPKeyword.isKeyword(directiveValue) and not CSPKeyword.isValue(directiveValue):
                    result.append(str(directiveValue))
        return result 


    @staticmethod
    def isNonce(nonce, opt_strict=False):
        """ checks whether the given string is a nonce

        Args:
            nonce (str): the nonce to be checked 
            opt_strict (bool): if true, the part after nonce- must be base64 encoded in order for the string to be a nonce
        """
        if nonce is None:
            return False
        strict_nonce_pattern = re.compile('^\'nonce-[a-zA-Z0-9+\/]+[=]{0,2}\'$')
        nonce_pattern = re.compile('^\'nonce-(.+)\'$')
        pattern = strict_nonce_pattern if opt_strict else nonce_pattern
        return bool(pattern.search(str(nonce)))

    @staticmethod
    def isHash(ihash, opt_strict=False):
        """ checks whether the given string is a hash

        Args:
            ihash (str): the hash to be checked 
            opt_strict (bool): if true, the part after shaxxx- must be base64 encoded in order for the string to be a hash
        """
        if ihash is None:
            return False
        strict_hash_pattern = re.compile('^\'(sha256|sha384|sha512)-[a-zA-Z0-9+/]+[=]{0,2}\'$')
        hash_pattern = re.compile('^\'(sha256|sha384|sha512)-(.+)\'$')
        pattern = strict_hash_pattern if opt_strict else hash_pattern
        return bool(pattern.search(str(ihash)))


