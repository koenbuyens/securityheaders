from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckWhitelistCDN(CSPCheck):
    def __init__(self, csp):
        self.csp = csp
    
    def check(self, opt_options=dict()):
        csp = self.csp
        if not csp:
            return []
        
        findings = []
        cdn = []
        if 'cdn' not in opt_options.keys():
            cdn = []
        elif 'cdn' in opt_options.keys():
            cdn = opt_options['cdn']
        effectiveScriptSrcDirective = csp.getEffectiveDirective(csp.directive.SCRIPT_SRC)
        scriptSrcValues = []
        try:
            scriptSrcValues = csp[effectiveScriptSrcDirective]
        except KeyError:
            scriptSrcValues = []
        for value in scriptSrcValues:            
            if value.startswith('\''):
                continue
            if Util.isUrlScheme(value) or value.find('.') == -1:
                continue

            url = '//' + Util.getSchemeFreeUrl(value)
            cdnbypass = Util.matchWildcardUrls(url, cdn)
            if cdnbypass:
                bypassDomain = ''
                bypassUrl = '//' + cdnbypass.netloc + cdnbypass.path
                bypassDomain = cdnbypass.netloc
                findings.append(Finding(csp.headerkey,FindingType.SCRIPT_WHITELIST_BYPASS,bypassDomain + ' is known to host many libraries which allow to bypass this CSP. Do not whitelist all scripts of a CDN.',FindingSeverity.HIGH, effectiveScriptSrcDirective, value))

        return findings
