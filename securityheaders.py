""" This script checks whether a URI returns secure security headers. The script implements various security checks, including the 
ones implemented by https://github.com/google/csp-evaluator and securityheaders.io as well as checks based on my own research. 
 

Run the script with python securityheaders.py -h for more information
"""

import httplib
import argparse
import socket 
import ssl
import sys
import re
import copy
import functools
import ipaddress
import os.path

from tabulate import tabulate
from urlparse import urlparse
from enum import Enum
from abc import ABCMeta, abstractmethod
from urlparse import urlparse


class Finding(object):
    def __init__(self, header, ftype, description, severity, opt_directive=None, opt_value=None):
        """ Constructor for a finding object.

        Args:
            header (HeaderType): the header for which this finding is valid
            ftype (FindingType): the type of finding
            description (str): the description of the finding
            severity (FindingSeverity): the severity of the finding
            opt_directive (Directive): if a header value has multiple keywords, then this is the keyword it was valid for
            opt_value (str): the insecure value   
        """

        self.header = header
        self.ftype = ftype
        self.description = description
        self.severity = severity
        self.directive = opt_directive
        self.value = opt_value

    def __str__(self):
        """ Returns a string representation of this finding  
        """
        return str(self.header) +"\t" + str(self.ftype) +"\t" + str(self.description) +"\t" + str(self.directive) + "\t" + str(self.value)


class FindingSeverity(Enum):
    CRITICAL = 0 #Critical severity
    HIGH = 10 #high severity
    MEDIUM = 30 #medium severity
    LOW = 55 #low severity
    INFO = 60 #informational severity
    NONE = 100 #no severity
    SYNTAX = 20 #syntax error
    HIGH_MAYBE = 40 #high severity, but needs to be confirmed by user
    STRICT_CSP = 45 #the CSP does not adhere to strict guidelines
    MEDIUM_MAYBE = 50 #medium severity, but needs to be confired by user

    def __str__(self):
        """ Returns a string representaiton of this finding severity   
        """
        return str(self.name.lower())    

class FindingType(Enum):
    #syntax issues
    MISSING_SEMICOLON = 100
    UNKNOWN_DIRECTIVE = 101
    INVALID_KEYWORD = 102

    #generic issues
    MISSING_HEADER = 103
    INSECURE_HEADER = 104
    MISSING_DIRECTIVES = 300

    #CSP-specific issues
    SCRIPT_UNSAFE_INLINE = 301
    SCRIPT_UNSAFE_EVAL = 302
    PLAIN_URL_SCHEMES = 303
    PLAIN_WILDCARD = 304
    SCRIPT_WHITELIST_BYPASS = 305
    OBJECT_WHITELIST_BYPASS = 306
    NONCE_LENGTH = 307
    IP_SOURCE = 308
    DEPRECATED_DIRECTIVE = 309
    SRC_HTTP = 310
    STRICT_DYNAMIC = 400
    STRICT_DYNAMIC_NOT_STANDALONE = 401
    NONCE_HASH = 402
    UNSAFE_INLINE_FALLBACK = 403
    WHITELIST_FALLBACK = 404
    IGNORED = 405

    def __str__(self):
        """ Returns a string representaiton of this finding type   
        """
        return str(self.name.lower())   

class HeaderType(Enum):
    CSP = 'content-security-policy'
    StrictTransportSecurity = 'strict-transport-security'
    XFrameOptions = 'x-frame-options'
    XPoweredBy = 'x-powered-by'
    Server = "server"
    XContentTypeOptions = 'x-content-type-options'
    XXSSProtection = 'x-xss-protection'
    AccessControlAllowOrigin = 'access-control-allow-origin'
    AccessControlMaxAge = 'access-control-max-age'
    ReferrerPolicy = 'referrer-policy'
    FeaturePolicy = 'feature-policy'

    def __str__(self):
        """ Returns a string representaiton of this header   
        """
        return str(self.value.lower())   
 

class CSPKeyword(Enum):
    SELF = "'self'"
    NONE = "'none'"
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    STRICT_DYNAMIC = "'strict-dynamic'"


    @staticmethod
    def isKeyword(keyword):
        """ Checks whether a given string is a CSP keyword.

        Args:
            keyword (str): the string to validate
        """
        return hasattr(CSPKeyword, keyword)


    def __str__(self):
        """ Returns a string representaiton of this CSP keyword   
        """
        return str(self.value.lower())   

class CSPDirective(Enum):
# Fetch directives
    CHILD_SRC = 'child-src'
    CONNECT_SRC = 'connect-src'
    DEFAULT_SRC = 'default-src'
    FONT_SRC = 'font-src'
    FRAME_SRC = 'frame-src'
    IMG_SRC = 'img-src'
    MEDIA_SRC = 'media-src'
    OBJECT_SRC = 'object-src'
    SCRIPT_SRC = 'script-src'
    STYLE_SRC = 'style-src'

    MANIFEST_SRC = 'manifest-src'
    WORKER_SRC = 'worker-src'

# Document directives
    BASE_URI = 'base-uri'
    PLUGIN_TYPES = 'plugin-types'
    SANDBOX = 'sandbox'
    DISOWN_OPENER = 'disown-opener'

# Navigation directives
    FORM_ACTION = 'form-action'
    FRAME_ANCESTORS = 'frame-ancestors'

# Reporting directives
    REPORT_TO = 'report-to'
    REPORT_URI = 'report-uri'

# Other directives
    BLOCK_ALL_MIXED_CONTENT = 'block-all-mixed-content'
    UPGRADE_INSECURE_REQUESTS = 'upgrade-insecure-requests'
    REFLECTED_XSS = 'reflected-xss'
    REFERRER = 'referrer'
    REQUIRE_SRI_FOR = 'require-sri-for'

    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, CSPDirective):
            return True
        return any(directive == item.value for item in cls)


    def endswith(self, value):
        return self.value.lower().endswith(value)

    def __str__(self):
        """ Returns a string representaiton of this CSP Directive   
        """
        return str(self.value.lower())   

class CSPVersion(Enum):
    CSP1 = 1
    CSP2 = 2
    CSP3 = 3

    def __lt__(self, other):
        """ Checks whether another CSPVersion is lower than this version

        Args:
            other (CSPVersion): the CSPVersion to compare with
        """
        return self.value < other.value

    def __eq__(self, other):
        """ Checks whether another CSPVersion is equal to this version

        Args:
            other (CSPVersion): the CSPVersion to compare with
        """
        return self.value == other.value

    def __ge__(self, other):
        """ Checks whether another CSPVersion is greater than this version

        Args:
            other (CSPVersion): the CSPVersion to compare with
        """
        return self.value > other.value

    def __str__(self):
        """ Returns a string representaiton of this CSP Version   
        """
        return str("CSP Version " + str(self.value))   

class Util(object):

    @staticmethod
    def isUrlScheme(urlScheme):
        """ Checks whether a string is an url scheme

        Args:
            urlScheme (str): string to check whether it is an url scheme
        """
        if not urlScheme:
            return False
        
        #an urlscheme can be anything that starts with alfanumeric charaters followed by a colon. 
        pattern = re.compile('^[a-zA-Z][+a-zA-Z0-9.-]*:$')
        return bool(pattern.search(urlScheme))

    @staticmethod
    def getSchemeFreeUrl(url):
        """ Removes the scheme from the url. E.g. https://www.google.com becomes www.google.com

        Args:
            url (str): string from which to remove the scheme
        """
        if not url:
            return None

        tmp = re.sub("^\w[+\w.-]*:\/\/", "", url, flags=re.IGNORECASE)
        tmp = re.sub("^\/\/", "", tmp, flags=re.IGNORECASE)  
        return tmp

    @staticmethod
    def matchWildcardUrls(url, listOfUrls):
        """ Checks whether wildcard host matches one of the given urls

        Args:
            url (str): host with potential wild card
            listOfUrls(list): list of urls that might be part of the host.
        """
        if not url or not listOfUrls:
            return None
        cspUrl = urlparse(url)
        host = cspUrl.netloc.lower() or ""
        hostHasWildcard = host.startswith("*.")
        wildcardFreeHost = re.sub("^\*", "", host, flags=re.IGNORECASE)
        path = cspUrl.path or ''
        hasPath = len(cspUrl.path) > 0 

        for url2 in listOfUrls:
            url = urlparse(str(url2))
            domain = url.netloc
            if (not domain.endswith(wildcardFreeHost)): 
                continue
            
            if (not hostHasWildcard and host != domain):
                continue

            if (hasPath):
                if (path.endswith('/')): 
                    if (not url.path.startswith(path)):
                        continue
                elif (url.path != path):
                    continue

            return url

        return None


class CSP(object):

    def __init__(self, unparsedstring):
        """ Constructor for a Content Security Policy

        Args:
            unparsedstring (str): CSP is created from the given string
        """
        self.parsedcsp = CSPParser().parse(unparsedstring)


    def __getitem__(self, index):
        """ returns the value of a given directive. If the directive does not exist, None is returned.

        Args:
            unparsedstring (str): CSP is created from the given string
        """
        if self.parsedcsp and index in self.parsedcsp:
            return self.parsedcsp[index]
        elif index not in self.parsedcsp:
            raise KeyError(str(index) + " not part of the policy")
        else:
            return None #only happens when self.parsedcsp is none

    def keys(self):
        if self.parsedcsp:
            return self.parsedcsp.keys()
        return []

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

    #these are unrusted domains and should not be used; taken from https://github.com/google/csp-evaluator
    with open(os.path.join(os.getcwd(), 'conf' ,'flashbypasses.txt'), 'r') as f:
        FLASH_WHITELIST_BYPASSES = f.read().splitlines()
    with open(os.path.join(os.getcwd(), 'conf' ,'angularwhitelistbypasses.txt'), 'r') as f:
        ANGULAR_WHITELIST_BYPASS = f.read().splitlines()
    with open(os.path.join(os.getcwd(), 'conf' ,'jsonpwhitelistbypasses.txt'), 'r') as f:
        JSONP_WHITELIST_BYPASS = f.read().splitlines()
    with open(os.path.join(os.getcwd(), 'conf' ,'jsonpwhitelistbypassneedseval.txt'), 'r') as f:
        JSONP_WHITELIST_BYPASS_NEEDS_EVAL = f.read().splitlines()


    def getEffectiveDirective(self, directive):
        """ returns the effective directive of a directive. Relevant for fetch directives which default to default-src when not specified

        Args:
            directive (CSPDirective): the directive for which we want to get the effective directive
        """
        # Only fetch directives default to default-src.
        if not directive or not self.parsedcsp:
            return directive
        if not(directive in self.parsedcsp) and directive in CSP.FETCH_DIRECTIVES:
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


    def getEffectiveCsp(self, cspVersion, findings=[]):
        """ returns the effective csp for a given version; i.e. removes keywords/directives that are not relevant

        Args:
            cspVersion (CSPVersion): the version for which we want to get the effective policy
            findings (list): a list of Findings that is modified when there are errors w.r.t. parsing; e.g. CSP3-only directive used in a CSP2 
        """
        effectiveCsp = CSP(None)
        effectiveCsp.parsedcsp = copy.deepcopy(self.parsedcsp)

        directive = self.getEffectiveDirective(CSPDirective.SCRIPT_SRC)
        values = []
        try:
            values = self[directive]
        except:
            values = []

        if not effectiveCsp.parsedcsp:
            return effectiveCsp

        if (directive in effectiveCsp.parsedcsp and (effectiveCsp.policyHasScriptNonces() or effectiveCsp.policyHasScriptHashes())):
            if cspVersion >= CSPVersion.CSP2:
            # Ignore 'unsafe-inline' in CSP >= v2, if a nonce or a hash is present.
                if CSPKeyword.UNSAFE_INLINE.value in values:
                    effectiveCsp[directive].remove(csp.Keyword.UNSAFE_INLINE)
                    findings.add(Finding(HeaderType.CSP, FindingType.IGNORED,'unsafe-inline is ignored if a nonce or a hash is present. (CSP2 and above)', FindingSeverity.NONE, directive, CSPKeyword.UNSAFE_INLINE))
            else:
            # remove nonces and hashes (not supported in CSP < v2).
                for value in values:
                    if value.startswith("'nonce-") or value.startswith("'sha"):
                        effectiveCsp[directive].remove(value)


        if directive in effectiveCsp.parsedcsp and self.policyHasStrictDynamic():
        # Ignore whitelist in CSP >= v3 in presence of 'strict-dynamic'.
            if cspVersion >= csp.Version.CSP3:
                for value in values:
                    if not value.startswith("'") or value == CSPKeyword.SELF or value == CSPKeyword.UNSAFE_INLINE.value:
                        effectiveCsp[directive].remove(value)
                        findings.add(Finding(HeaderType.CSP, FindingType.IGNORED, 'Because of strict-dynamic this entry is ignored in CSP3 and above',FindingSeverity.NONE, directive, value))
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
        return bool(pattern.search(nonce))

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
        return bool(pattern.search(ihash))


class Checker():
    __metaclass__ = ABCMeta

    @abstractmethod
    def check(self, tocheck, opt_options=[]):
        pass

class CSPChecker(Checker):

    def extractcsp(self, headers):
        if not headers:
            return None

        if HeaderType.CSP.value in headers.keys():
            return CSP(headers[HeaderType.CSP.value])
        else:
            return None

    def extractEffectiveCSP(self, headers, opt_options=[], opt_findings=[]):
        csp = self.extractcsp(headers) 
        if not csp:
            return None
        if 'CSPversion' in opt_options:
            version = opt_options['CSPversion']
        else:
            version = CSPVersion.CSP3
        return csp.getEffectiveCsp(version, opt_findings)


    def extractEffectiveDirective(self, headers, directive, options, opt_findings = []):
        csp = self.extractEffectiveCSP(headers, options, opt_findings)
        if not csp:
            return None
        return csp.getEffectiveDirective(CSPDirective.SCRIPT_SRC)



    def effectiveDirectiveValues(self, headers, actualdirective, options):
        csp = self.extractEffectiveCSP(headers, options)
        if not csp:
            return []
        directive = csp.getEffectiveDirective(actualdirective)       
        if not directive:
            return []

        values = []
        try:
            values = csp[directive]
        except:
            values = []
        return values


    def applyCheckFunktionToDirectives(self, parsedCsp, check, findings, opt_directives=[]):
        directiveNames = []
        if parsedCsp:
            directiveNames = parsedCsp.keys()
        if opt_directives:
            directiveNames = opt_directives
        for directive in directiveNames:
            directiveValues = parsedCsp[directive]
            if directiveValues:
                check(directive, directiveValues, findings)        

#checks whether unsafe-inline has been used.
# unsafe-inline for script-src (or for default-src when no script-src is provided) allows execution of inline third-party JavaScript.
class CSPUnsafeInlineChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        if not headers:
            return []
        directive = CSPDirective.SCRIPT_SRC
        values = CSPChecker.effectiveDirectiveValues(self, headers,directive, opt_options)
        # Check if unsafe-inline is present.
        if CSPKeyword.UNSAFE_INLINE.value in values:
            return [Finding(HeaderType.CSP, FindingType.SCRIPT_UNSAFE_INLINE, '\'' + CSPKeyword.UNSAFE_INLINE.value + '\' allows the execution of unsafe in-page scripts and event handlers.',FindingSeverity.HIGH, directive, CSPKeyword.UNSAFE_INLINE.value)]
        return []


#checks whether unsafe-eval has been used
class CSPUnsafeEvalChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        if not headers:
            return []
        directive = CSPDirective.SCRIPT_SRC
        values = CSPChecker.effectiveDirectiveValues(self, headers,directive, opt_options)
        # Check if unsafe-eval is present.
        if (CSPKeyword.UNSAFE_EVAL.value in values):
            return [Finding(HeaderType.CSP, FindingType.SCRIPT_UNSAFE_EVAL, '\'' + CSPKeyword.UNSAFE_EVAL.value + '\' allows the execution of code injected into DOM APIs such as eval().',FindingSeverity.MEDIUM_MAYBE, directive, CSPKeyword.UNSAFE_EVAL.value)]
        return []


#checks whether data: or http: has been used
#  allowing URLs that start with data: are equivalent to unsafe-inline.
class CSPPlainUrlSchemesChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        findings = []
        csp = CSPChecker.extractcsp(self, headers) 

        if not csp or not csp.parsedcsp:
            return findings


        directivesToCheck = csp.getEffectiveDirectives(CSP.DIRECTIVES_CAUSING_XSS)
        for directive in directivesToCheck:
            values = []
            if directive in csp.parsedcsp:
                values = csp[directive]
            for value in values:
                if value in CSP.URL_SCHEMES_CAUSING_XSS:
                    findings.append(Finding(HeaderType.CSP, FindingType.PLAIN_URL_SCHEMES,  value + ' URI in ' + directive.value + ' allows the execution of unsafe scripts.',FindingSeverity.HIGH, directive, value))

        return findings


#checks whether * has been used
#The directive 'script-src' should not be set to *, as it allows loading of arbitrary JavaScript. T
#The directive 'object-src' should not be set to *, as it allows loading of arbitrary plugins that can execute JavaScript (e.g. Flash).
class CSPWildCardChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp or not csp.parsedcsp:
            return []

        findings = []

        directivesToCheck = csp.getEffectiveDirectives(CSP.DIRECTIVES_CAUSING_XSS)

        for directive in directivesToCheck:
            values = []
            if directive in csp.parsedcsp:
                values = csp[directive]
            
            for value in values:
                url = Util.getSchemeFreeUrl(value)
                if '*' in url and len(url) == 1:
                    findings.append(Finding(HeaderType.CSP, FindingType.PLAIN_WILDCARD, directive.value + ' should not allow \'*\' as source. This may enable execution of malicious JavaScript.',FindingSeverity.HIGH, directive, value))

        return findings


#checks whether object-src or base-uri or default-src or ... is missing
# The default-src directive should be set as a fall-back when restrictions have not been specified.
class CSPMissingDirectiveChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp:
            return []

        findings = []

        directivesCausingXss = CSP.DIRECTIVES_CAUSING_XSS
        if csp.parsedcsp and CSPDirective.DEFAULT_SRC in csp.parsedcsp:
            defaultSrcValues = csp[CSPDirective.DEFAULT_SRC]
            if not CSPDirective.OBJECT_SRC in csp.parsedcsp and not CSPKeyword.NONE in defaultSrcValues:
                findings.append(Finding(HeaderType.CSP, FindingType.MISSING_DIRECTIVES, 'Can you restrict object-src to \'none\'?',FindingSeverity.HIGH_MAYBE, CSPDirective.OBJECT_SRC))
            if CSPDirective.BASE_URI in csp.parsedcsp:
                return findings
            else:
                directivesCausingXss = [CSPDirective.BASE_URI]
        else:
            findings.append(Finding(HeaderType.CSP, FindingType.MISSING_DIRECTIVES,"The default-src directive should be set as a fall-back when other restrictions have not been specified. ",FindingSeverity.HIGH,CSPDirective.DEFAULT_SRC))            

        for directive in directivesCausingXss:
            if not csp.parsedcsp or not directive in csp.parsedcsp:
                description = directive.value + ' directive is missing.'
                if directive == CSPDirective.OBJECT_SRC:
                    description = 'Missing object-src allows the injection of plugins which can execute JavaScript. Can you set it to \'none\'?'
                elif directive == CSPDirective.BASE_URI:
                    if not csp.policyHasScriptNonces() and not csp.policyHasScriptHashes() and csp.policyHasStrictDynamic():
                        continue
                    description = 'Missing base-uri allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. Can you set it to \'none\' or \'self\'?'
                findings.append(Finding(HeaderType.CSP, FindingType.MISSING_DIRECTIVES,description,FindingSeverity.HIGH,directive))
        
        return findings 

#Checks whether the CSP has Unknown Directives
class CSPUnknownDirectiveChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp:
            return []

        findings = []

        for directive in csp.keys():
            if not CSPDirective.isDirective(directive):
                if directive.endswith(':'):
                    findings.append(Finding(HeaderType.CSP, FindingType.UNKNOWN_DIRECTIVE,"CSP directives don't end with a colon.",FindingSeverity.SYNTAX, None, directive))
                else:
                    findings.append(Finding(HeaderType.CSP, FindingType.UNKNOWN_DIRECTIVE,'Directive "' + str(directive) + '" is not a known CSP directive.',FindingSeverity.SYNTAX,None, directive))

        return findings

# Syntax checker
class CSPMissingColumnChecker(CSPChecker):

    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp:
            return []

        findings = []

        for directive in csp.keys():
            for value in csp[directive]:
                if CSPDirective.isDirective(value):
                    findings.append(Finding(HeaderType.CSP, FindingType.MISSING_SEMICOLON,'Did you forget the semicolon?"' + value + '" seems to be a directive, not a value',FindingSeverity.SYNTAX, directive, value))
        return findings

class CSPFlashObjectWhitelistBypassChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp or not csp.parsedcsp:
            return []

        findings = []

        directive = csp.getEffectiveDirective(CSPDirective.OBJECT_SRC)
        objectSrcValues = []
        try:
            objectSrcValues = csp[directive]
        except KeyError:
            objectSrcValues = []
        if CSPDirective.PLUGIN_TYPES in csp.parsedcsp:
            pluginTypes = csp[CSPDirective.PLUGIN_TYPES]
        else:
            pluginTypes = None

        if pluginTypes and not 'application/x-shockwave-flash' in pluginTypes:
            return []

        for value in objectSrcValues:
            if value == CSPKeyword.NONE.value:
                return []

            url = '//' + Util.getSchemeFreeUrl(value)
            flashBypass = Util.matchWildcardUrls(url, csp.FLASH_WHITELIST_BYPASSES)
            if (flashBypass):
                findings.append(Finding(HeaderType.CSP, FindingType.OBJECT_WHITELIST_BYPASS, flashBypass.netloc + ' is known to host Flash files which allow to bypass this CSP.',FindingSeverity.HIGH, directive, value))
            elif (directive == CSPDirective.OBJECT_SRC):
                findings.append(Finding(HeaderType.CSP, FindingType.OBJECT_WHITELIST_BYPASS, 'Can you restrict object-src to \'none\' only?',FindingSeverity.MEDIUM_MAYBE, directive,value))

        return findings


# checks whether allowed source is e.g. localhost
class CSPIPSourceChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp:
            return []

        findings = []

        CSPChecker.applyCheckFunktionToDirectives(self, csp.parsedcsp, self.checkIP, findings)
        return findings

    def checkIP(self, directive, directiveValues, findings):
        for value in directiveValues:
            url = '//' + Util.getSchemeFreeUrl(value)
            host = urlparse(url).netloc
            ip = None
            validip = True
             
            try:
                ip = ipaddress.ip_address(u''+host)
            except ValueError:
                validip = False
            if validip:
                ipString = str(ip) + ''

                if '127.0.0.1' in ipString:
                    findings.append(Finding(HeaderType.CSP,FindingType.IP_SOURCE, directive.value + ' directive allows localhost as source. Please make sure to remove this in production environments.',FindingSeverity.INFO, directive, value))
                else:
                    findings.append(Finding(HeaderType.CSP,FindingType.IP_SOURCE, directive.value + ' directive has an IP-Address as source: ' + ipString + ' (will be ignored by browsers!). ', FindingSeverity.INFO, directive, value))

# checks whether CSP header has been configured with an empty policy. 
# It does not protect the application against any attacks as no directives are configured.
class CSPEmptyChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp:
            return []

        findings = []
        if not csp.parsedcsp or len(csp.parsedcsp) == 0:
            findings.append(Finding(HeaderType.CSP,FindingType.MISSING_HEADER,'CSP header is empty.', FindingSeverity.MEDIUM, "Content-Security-Policy"))
        return findings

#checks whether csp of v3 contains report-uri
class CSPDeprecatedDirectiveChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp or not csp.parsedcsp:
            return []

        findings = []

        if CSPDirective.REPORT_URI in csp.parsedcsp:
            findings.append(Finding(HeaderType.CSP,FindingType.DEPRECATED_DIRECTIVE,'report-uri is deprecated in CSP3. Please use the report-to directive instead.', FindingSeverity.INFO, CSPDirective.REPORT_URI))
        return findings


#checks nonce length to be at least 8 characters
#checks nonce length to be base64
class CSPNonceLengthChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp:
            return []

        findings = []

        CSPChecker.applyCheckFunktionToDirectives(self, csp.parsedcsp, self.checkNonce, findings)
        return findings


    def checkNonce(self, directive, directiveValues, findings):
        nonce_pattern = re.compile("^'nonce-(.+)'$")
        for value in directiveValues:
            match = nonce_pattern.search(value)
            #nonce value starts with nonce- but does not have an actual value
            if not bool(match) and "nonce-" in value:
                findings.append(Finding(HeaderType.CSP,FindingType.NONCE_LENGTH,'Nonces should be at least 8 characters long.',FindingSeverity.MEDIUM, directive, value))
            #no nonce value in the directive value
            if not bool(match):
                continue
            #nonce value in the directive value
            else:
                #get the value of the nonce; i.e. everything after nonce-
                nonceValue = match.group(1)
                if len(nonceValue) < 8:
                    findings.append(Finding(HeaderType.CSP,FindingType.NONCE_LENGTH,'Nonces should be at least 8 characters long.',FindingSeverity.MEDIUM, directive, value))
                if not CSP.isNonce(value, True):
                    findings.append(Finding(HeaderType.CSP,FindingType.NONCE_LENGTH,'Nonces should only use the base64 charset.',FindingSeverity.INFO, directive, value))


#checks wheter URIs are NOT http:
class CSPSCRHTTPChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp:
            return []

        findings = []

        CSPChecker.applyCheckFunktionToDirectives(self, csp.parsedcsp, self.checksrchttp, findings)
        return findings

    def checksrchttp(self, directive, directiveValues, findings):
        for value in directiveValues:
            description = None
            if directive == CSPDirective.REPORT_URI:
                description = 'Use HTTPS to send violation reports securely.'
            else:
                description = 'Allow only resources downloaded over HTTPS.'
            if value.startswith('http://'):
                findings.append(Finding(HeaderType.CSP, FindingType.SRC_HTTP,description,FindingSeverity.MEDIUM, directive, value))



#checks whether CSP cam be bypassed (JSONP)
class CSPScriptWhitelistBypassChecker(CSPChecker):
    def check(self, headers, opt_options=dict()): 
        csp = CSPChecker.extractcsp(self, headers) 
        if not csp or not csp.parsedcsp:
            return []

        findings = []

        effectiveScriptSrcDirective = csp.getEffectiveDirective(CSPDirective.SCRIPT_SRC)
        scriptSrcValues = []
        try:
            scriptSrcValues = csp[effectiveScriptSrcDirective]
        except KeyError:
            scriptSrcValues = []

        for value in scriptSrcValues:
            if value == CSPKeyword.SELF.value:
                findings.append(Finding(HeaderType.CSP,FindingType.SCRIPT_WHITELIST_BYPASS,'\'self\' can be problematic if you host JSONP, Angular or user uploaded files.',FindingSeverity.MEDIUM_MAYBE, effectiveScriptSrcDirective,value))
                continue

            if value.startswith('\''):
                continue
            if Util.isUrlScheme(value) or value.find('.') == -1:
                continue

            url = '//' + Util.getSchemeFreeUrl(value)
            angularBypass = Util.matchWildcardUrls(url, csp.ANGULAR_WHITELIST_BYPASS)
            jsonpBypass = Util.matchWildcardUrls(url, csp.JSONP_WHITELIST_BYPASS)

            if jsonpBypass:
                bypassUrl = '//' + jsonpBypass.netloc + jsonpBypass.path
                evalRequired = jsonpBypass.netloc in csp.JSONP_WHITELIST_BYPASS_NEEDS_EVAL
                evalPresent = CSPKeyword.UNSAFE_EVAL in scriptSrcValues
                if evalRequired and not evalPresent:
                    jsonpBypass = None
            if jsonpBypass or angularBypass:
                bypassDomain = ''
                bypassTxt = ''
                if jsonpBypass:
                    bypassDomain = jsonpBypass.netloc
                    bypassTxt = ' JSONP endpoints'
                if angularBypass:
                    bypassDomain = angularBypass.netloc
                    if not bypassTxt:
                        bypassTxt += ''
                    else: 
                        bypassTxt += ' and'
                    bypassTxt += ' Angular libraries'
                findings.append(Finding(HeaderType.CSP,FindingType.SCRIPT_WHITELIST_BYPASS,bypassDomain + ' is known to host' + bypassTxt + ' which allow to bypass this CSP.',FindingSeverity.HIGH, effectiveScriptSrcDirective, value))
            else:
                findings.append(Finding(HeaderType.CSP, FindingType.SCRIPT_WHITELIST_BYPASS,'No bypass found; make sure that this URL doesn\'t serve JSONP replies or Angular libraries.',FindingSeverity.MEDIUM_MAYBE, effectiveScriptSrcDirective,value))
        return findings
 

# checks whether headers have known good or bad values
class BadValueChecker(Checker):
    def check(self, headers, header, badvalues, description, opt_severity=FindingSeverity.LOW, opt_options=dict(), bad=True):
        if not headers or not header or not badvalues or not header.value:
            return []

        value = None
        finding = [Finding(header, FindingType.INSECURE_HEADER, description,opt_severity, header.value, value)]

        try:
            if not bad and not headers[header.value]:
                return finding
        except KeyError:
            return []

        if header.value in headers.keys():
            value = headers[header.value]
            if bad:
                if value.lower() in badvalues:
                    return finding
            else:
                 if not value.lower() in badvalues:
                    return finding
        return []

class XFrameOptionsGoodChecker(BadValueChecker):
    def check(self, headers, opt_options=dict()):
        #deny and sameorigin are the only good values
        return BadValueChecker.check(self, headers, HeaderType.XFrameOptions, ['deny', 'sameorigin'], 'This header tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking. The recommended value is "x-frame-options: SAMEORIGIN."', FindingSeverity.MEDIUM, opt_options, False)

class ReferrerPolicyInsecureChecker(BadValueChecker):
    def check(self, headers, opt_options=dict()):
        #these are known bad values
        return BadValueChecker.check(self, headers, HeaderType.ReferrerPolicy, ['unsafe-url', 'origin-when-cross-origin'], ' If this policy is set, it should not use unsafe-url and origin-when-cross-origin as it can transfer sensitive information (via the Referer header) from HTTPS environments to HTTP environments.', FindingSeverity.LOW, opt_options)

class XContentTypeOptionsNoSniffChecker(BadValueChecker):
    def check(self, headers, opt_options=dict()):
        #the only valid value is nosniff
        return BadValueChecker.check(self, headers, HeaderType.XContentTypeOptions, ['nosniff'], 'This header stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is "X-Content-Type-Options: nosniff"', FindingSeverity.MEDIUM, opt_options, False)

class XSSSProtectionBlockChecker(BadValueChecker):
    def check(self, headers, opt_options=dict()):
        return BadValueChecker.check(self, headers, HeaderType.XXSSProtection, ['1', '1; mode=block'], 'This header sets the configuration for the cross-site scripting filter built into most browsers. The recommended value is "X-XSS-Protection: 1; mode=block".', FindingSeverity.LOW, opt_options, False)

class AccessControlAllowOriginStarChecker(BadValueChecker):
    def check(self, headers, opt_options=dict()):
        return BadValueChecker.check(self, headers, HeaderType.AccessControlAllowOrigin, ['*'], 'TODO', FindingSeverity.MEDIUM, opt_options)

class CORSPreflightTimeTooLongChecker(Checker):
    def check(self, headers, opt_options=dict()):
        if 'access-control-max-age' in headers.keys():
            value = headers['access-control-max-age']
            if value.lower() > 1800:
                return [Finding(HeaderType.AccessControlMaxAge, FindingType.INSECURE_HEADER, "Access-Control-Max-Age set to a too large value. This header is used by the server to explicitly instruct browsers to cache responses to CORS requests. An excessively long cache timeout increases the risk that changes to a server's CORS policy will not be honored as they still use a cached response.",FindingSeverity.LOW, "Access-Control-Max-Age", value)]
        return []


# missing security headers
class HeaderMissingChecker(Checker):
    def check(self, headers, header, description, options):
        if not header or not header.value:
           return []

        result = [Finding(header, FindingType.MISSING_HEADER, header.value + ' header not present. ' + description,FindingSeverity.INFO, header.value)]

        if not headers:
            return result
        if not header.value.lower() in headers.keys():
            return result
        return []     

class CSPMissingChecker(HeaderMissingChecker):
    def check(self, headers, opt_options=dict()):
        return HeaderMissingChecker.check(self, headers, HeaderType.CSP, 'This header protects against XSS attacks. By whitelisting sources of approved content, the browser does not load malicious assets.', opt_options)         

class StrictTransportSecurityMissingChecker(HeaderMissingChecker):
    def check(self, headers, opt_options=dict()):
        return HeaderMissingChecker.check(self, headers, HeaderType.StrictTransportSecurity, 'This header strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS. The recommended value us "strict-transport-security: max-age=31536000; includeSubDomains".', opt_options)         
#TODO: check max-age

class XFrameOptionsMissingChecker(HeaderMissingChecker):
    def check(self, headers, opt_options=dict()):
        return HeaderMissingChecker.check(self, headers, HeaderType.XFrameOptions, 'This header tells the browser whether the site can be framed. Not allowing framing defends against clickjacking attacks.', opt_options)         

class XContentTypeOptionsMissingChecker(HeaderMissingChecker):
    def check(self, headers, opt_options=dict()):
        return HeaderMissingChecker.check(self, headers, HeaderType.XContentTypeOptions, 'This header stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is "X-Content-Type-Options: nosniff".', opt_options)         

class ReferrerPolicyMissingChecker(HeaderMissingChecker):
    def check(self, headers, opt_options=dict()):
        return HeaderMissingChecker.check(self, headers, HeaderType.ReferrerPolicy, 'It is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites.', opt_options)         

class FeaturePolicyMissingChecker(HeaderMissingChecker):
    def check(self, headers, opt_options=dict()):
        return HeaderMissingChecker.check(self, headers, HeaderType.FeaturePolicy, 'It is a new header that allows a site to control which features and APIs can be used in the browser.', opt_options)         

class XSSSProtectionMissingChecker(HeaderMissingChecker):
    def check(self, headers, opt_options=dict()):
        return HeaderMissingChecker.check(self, headers, HeaderType.XXSSProtection, 'This header stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is "X-Content-Type-Options: nosniff".', opt_options)       


# Info disclosure headers
class HeaderPresentChecker(Checker):
    def check(self, headers, header, description, options):
        if not header or not header.value or not headers:
           return []

        if header.value in headers.keys():
            return [Finding(header, FindingType.INSECURE_HEADER, header.value + ' header present. ' + description,FindingSeverity.INFO, header.value, headers[header.value])]
        return []   

class XPoweredByPresentChecker(HeaderPresentChecker):
    def check(self, headers, opt_options=dict()):
        return HeaderPresentChecker.check(self, headers, HeaderType.XPoweredBy, 'This header gives an attacker info for more targeted attacks.', opt_options)         

class ServerPresentChecker(HeaderPresentChecker):
    def check(self, headers, opt_options=dict()):
        return HeaderPresentChecker.check(self, headers, HeaderType.Server, 'This header gives an attacker info for more targeted attacks.', opt_options)         

class HeaderEvaluator(object):

    DEFAULT_CHECKS = [
       "CSPMissingChecker",
       "CSPEmptyChecker",
       "CSPUnknownDirectiveChecker",
       "CSPMissingColumnChecker",
       "CSPUnsafeInlineChecker",
       "CSPUnsafeEvalChecker",
       "CSPPlainUrlSchemesChecker",
       "CSPWildCardChecker",
       "CSPMissingDirectiveChecker",
       "CSPFlashObjectWhitelistBypassChecker",
       "CSPIPSourceChecker",
       "CSPDeprecatedDirectiveChecker",
       "CSPNonceLengthChecker",
       "CSPSCRHTTPChecker",
       "CSPScriptWhitelistBypassChecker",
       "StrictTransportSecurityMissingChecker",
       "XFrameOptionsMissingChecker",
       "XPoweredByPresentChecker",
       "ServerPresentChecker",
       "XContentTypeOptionsMissingChecker",
       "XContentTypeOptionsNoSniffChecker",
       "XSSSProtectionMissingChecker",
       "XSSSProtectionBlockChecker",
       "AccessControlAllowOriginStarChecker",
       "CORSPreflightTimeTooLongChecker",
       "ReferrerPolicyMissingChecker",
       "ReferrerPolicyInsecureChecker",
       "FeaturePolicyMissingChecker"
    ]

    def __init__(self, headers):
        self.headers = dict()
        for header in headers:
            self.headers[header[0]] = header[1]
        self.findings = []
        self.options = []

    def evaluate(self, opt_options=dict()): 
        self.findings = []
        checks = self.DEFAULT_CHECKS
        if 'checks' in opt_options:
            checks = opt_options['checks']


        for check in checks:
            self.findings = self.findings + globals()[check]().check(self.headers, opt_options)

        return self.findings

class CSPParser(object):
    def __init__(self):
        pass

    def parse(self, unparsedCsp):
        csp = {}
        if unparsedCsp:
            directiveTokens = unparsedCsp.split(';')
            for directiveToken in directiveTokens:
                directiveToken.strip();

                """ Split directive tokens into directive name and directive values. """
                directiveParts = directiveToken.split()
                if isinstance(directiveParts, list) and not isinstance(directiveParts, (str, unicode)) and len(directiveParts) > 0:
                    directiveName = directiveParts[0].lower()
                    try:
                        directive = CSPDirective(directiveName)
                    except ValueError:
                        directive = directiveName #koen: parser erorr, unknown directive; should be a finding
                    csp[directive] = []
                    for directiveValue in directiveParts[1:]:
                        csp[directive].append(self.normalizeDirectiveValue(directiveValue))
            return csp;

    def normalizeDirectiveValue(self, directiveValue):
        directiveValue = directiveValue.strip()
        directiveValueLower = directiveValue.lower()
        if (CSPKeyword.isKeyword(directiveValueLower) or Util.isUrlScheme(directiveValue)):
            return directiveValueLower
        return directiveValue

class SecurityHeaders(object):
    def __init__(self):
        pass

    def check_headers(self, url, follow_redirects = 0, options=dict()):
        """ Make the HTTP request and check if any of the pre-defined
        headers exists.

        Args:
            url (str): Target URL in format: scheme://hostname/path/to/file
            follow_redirects (Optional[str]): How deep we follow the redirects, 
            value 0 disables redirects.
        """

        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if (protocol == 'http'):
            conn = httplib.HTTPConnection(hostname)
        elif (protocol == 'https'):
                # on error, retry without verifying cert
                # in this context, we're not really interested in cert validity
                conn = httplib.HTTPSConnection(hostname, context = ssl._create_unverified_context() )
        else:
            """ Unknown protocol scheme """
            return {}
    
        try:
            conn.request('GET', path)
            res = conn.getresponse()
            headers = res.getheaders()
            print headers
        except socket.gaierror:
            print 'HTTP request failed'
            return False

        """ Follow redirect """
        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0] == 'location'):
                    return self.check_headers(header[1], follow_redirects - 1, options) 
                
        """ Loop through headers and evaluate the risk """
        evaluator = HeaderEvaluator(headers)
        return evaluator.evaluate(options)

if __name__ == "__main__":
    #TODO: implement configrable ratings
    #TODO: implement configerable checkers (i.e. what to be used)
    #TODO: CORS - null origin
    #TODO: CORS - Only Allow HTTPS Origins for Requests with Credentials
    parser = argparse.ArgumentParser(description='Check HTTP security headers', \
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--cspversion', dest='csp_version', metavar='V', default=3, type=int, help='CSP Version to be checked')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int, help='Max redirects, set 0 to disable')
    parser.add_argument('--config', dest='configfile', metavar='C', default="config.json", type=str, help='Path to config file')
    args = parser.parse_args()
    url = args.url
    redirects = args.max_redirects
    cspversion = CSPVersion(args.csp_version)

    options = dict()
    options['CSPVersion'] = cspversion
    

    foo = SecurityHeaders()

    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url # default to http if scheme not provided


    findings = foo.check_headers(url, redirects, options)

    if not findings:
        print "No findings were found." 
        sys.exit(1)


    Red = '\033[91m'
    Green = '\033[92m'
    White = '\033[97m'
    Yellow = '\033[93m'
    Grey = '\033[90m'
    Black = '\033[90m'
    Default = '\033[99m'
    endColor = '\033[0m'

    table = []

    for finding in findings:
        if finding.severity == FindingSeverity.MEDIUM or finding.severity == FindingSeverity.MEDIUM_MAYBE:
            color = Yellow
        elif finding.severity == FindingSeverity.HIGH or finding.severity == FindingSeverity.HIGH_MAYBE:
            color = Red
        elif finding.severity == FindingSeverity.LOW:
            color = Green
        elif finding.severity == FindingSeverity.SYNTAX or finding.severity == FindingSeverity.STRICT_CSP or finding.severity == FindingSeverity.INFO:
            color = Grey
        else:
            color = Default

        table.append([color + str(finding.severity.name) + endColor +"", finding.header.value, finding.ftype.name.lower(), finding.directive, finding.value, finding.description])
        #print '[' + color + str(finding.severity.name) + endColor + ']\t' + finding.description

    print tabulate(table, headers=["Severity", "Header", "Finding Type", "Directive", "Value","Description"])
