#checks whether CSP cam be bypassed (JSONP)

from securityheaders import Util

from securityheaders.models.csp import CSPKeyword, CSP
from securityheaders.checkers import Finding, FindingType, FindingSeverity
from checker import CSPChecker

class CSPScriptWhitelistBypassChecker(CSPChecker):
    def myoptions(cls):
        return {'angular':list, 'jsonp':list, 'jsonpeval':list}

    def check(self, headers, opt_options=dict()): 
        csp = self.getcsp(headers) 
        if not csp or not csp.parsedstring:
            return []

        findings = []
        angular = []
        jsonp = []
        jsonpeval = []
        me = self.__class__.__name__
        if me in opt_options.keys() and 'angular' not in opt_options[me].keys():
            angular = []
        elif me in opt_options.keys() and 'angular' in opt_options[me].keys():
            angular = opt_options[me]['angular']
        if me in opt_options.keys() and 'jsonp' not in opt_options[me].keys():
            jsonp = []
        if me in opt_options.keys() and 'jsonp' in opt_options[me].keys():
            jsonp = opt_options[me]['jsonp']
        if me in opt_options.keys() and 'jsonpeval' not in opt_options[me].keys():
            jsonpeval = []
        if me in opt_options.keys() and 'jsonpeval' in opt_options[me].keys():
            jsonpeval = opt_options[me]['jsonpeval']

        effectiveScriptSrcDirective = csp.getEffectiveDirective(CSP.directive.SCRIPT_SRC)
        scriptSrcValues = []
        try:
            scriptSrcValues = csp[effectiveScriptSrcDirective]
        except KeyError:
            scriptSrcValues = []

        for value in scriptSrcValues:
            if value == CSPKeyword.SELF or value==str(CSPKeyword.SELF):
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
                findings.append(Finding(csp.headerkey,FindingType.SCRIPT_WHITELIST_BYPASS,bypassDomain + ' is known to host' + bypassTxt + ' which allow to bypass this CSP.',FindingSeverity.HIGH, effectiveScriptSrcDirective, value))
            else:
                findings.append(Finding(csp.headerkey, FindingType.SCRIPT_WHITELIST_BYPASS,'No bypass found; make sure that this URL doesn\'t serve JSONP replies or Angular libraries.',FindingSeverity.MEDIUM_MAYBE, effectiveScriptSrcDirective,value))
        return findings
