from securityheaders.checkers import Finding, FindingType, FindingSeverity
from securityheaders import Util
from .cspcheck import CSPCheck

class CSPCheckWhitelist(CSPCheck):
    def __init__(self, csp):
        self.csp = csp
    
    def check(self, opt_options=dict()):
        csp = self.csp
        if not csp:
            return []
        
        findings = []
        angular = []
        jsonp = []
        jsonpeval = []
        if 'angular' not in opt_options.keys():
            angular = []
        elif 'angular' in opt_options.keys():
            angular = opt_options['angular']
        if 'jsonp' not in opt_options.keys():
            jsonp = []
        if 'jsonp' in opt_options.keys():
            jsonp = opt_options['jsonp']
        if 'jsonpeval' not in opt_options.keys():
            jsonpeval = []
        if 'jsonpeval' in opt_options.keys():
            jsonpeval = opt_options['jsonpeval']
        
        effectiveScriptSrcDirective = csp.getEffectiveDirective(csp.directive.SCRIPT_SRC)
        scriptSrcValues = []
        try:
            scriptSrcValues = csp[effectiveScriptSrcDirective]
        except KeyError:
            scriptSrcValues = []
        for value in scriptSrcValues:
            if value == csp.keyword.SELF or value==str(csp.keyword.SELF):
                findings.append(Finding(csp.headerkey,FindingType.SCRIPT_WHITELIST_BYPASS,'\'self\' can be problematic if you host JSONP, Angular or user uploaded files.',FindingSeverity.MEDIUM_MAYBE, effectiveScriptSrcDirective,value))
                continue
            
            if value.startswith('\''):
                continue
            if Util.isUrlScheme(value) or value.find('.') == -1:
                continue

            url = '//' + Util.getSchemeFreeUrl(value)
            angularBypass = Util.matchWildcardUrls(url, angular)
            jsonpBypass = Util.matchWildcardUrls(url, jsonp)
                        
            if jsonpBypass:
                bypassUrl = '//' + jsonpBypass.netloc + jsonpBypass.path
                evalRequired = jsonpBypass.netloc in  jsonpeval
                evalPresent = csp.keyword.UNSAFE_EVAL in scriptSrcValues
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
                    findings.append(Finding(csp.headerkey,FindingType.SCRIPT_WHITELIST_BYPASS,bypassDomain + ' is known to host' + bypassTxt + ' which allow to bypass this CSP.',FindingSeverity.HIGH, effectiveScriptSrcDirective, value))
            else:
                findings.append(Finding(csp.headerkey, FindingType.SCRIPT_WHITELIST_BYPASS,'No bypass found; make sure that this URL doesn\'t serve JSONP replies or Angular libraries.',FindingSeverity.MEDIUM_MAYBE, effectiveScriptSrcDirective,value))
        return findings
