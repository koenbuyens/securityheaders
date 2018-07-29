from securityheaders import *
from urlparse import urlparse

import unittest
#should use mock and proper unit tests. 

class UtilTest(unittest.TestCase):
    def test_isUrlSchemeNone(self):
        self.assertFalse(Util.isUrlScheme(None))

    def test_isUrlSchemeHttp(self):
        self.assertTrue(Util.isUrlScheme('http:'))

    def test_isUrlSchemeHttps(self):
        self.assertTrue(Util.isUrlScheme('https:'))

    def test_isUrlSchemeInvalid(self):
        self.assertFalse(Util.isUrlScheme('noscheme'))
        
    def test_getSchemeFreeUrlValid(self):
        self.assertEqual(Util.getSchemeFreeUrl('http://www.synopsys.com'), 'www.synopsys.com')

    def test_getSchemeFreeUrlCapitals(self):
        self.assertEqual(Util.getSchemeFreeUrl('HTTPS://www.synopsys.com'), 'www.synopsys.com')

    def test_getSchemeFreeUrlNone(self):
        self.assertEqual(Util.getSchemeFreeUrl(None), None)

    def test_matchWildcardUrls(self):
        urls = [
        '//vk.com/swf/video.swf',
        '//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'

        ]
        self.assertEquals(Util.matchWildcardUrls('https://*.vk.com', urls), None)
        self.assertEquals(Util.matchWildcardUrls('https://ajax.googleapis.com', urls), urlparse('//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'))
        self.assertEquals(Util.matchWildcardUrls('https://*.googleapis.com', urls), urlparse('//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'))
        self.assertEquals(Util.matchWildcardUrls(None, urls), None)
        self.assertEquals(Util.matchWildcardUrls('https://*.googleapis.com', None), None)
        self.assertEquals(Util.matchWildcardUrls('https://*.googleapis.com', []), None)
#        self.assertEquals(Util.matchWildcardUrls('*.googleapis.com', urls), urlparse('//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'))





class CSPTest(unittest.TestCase):
    def setUp(self):
        self.csphash = CSP("default-src 'self'; script-src 'sha256-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw='")
        self.csphashincorrect = CSP("default-src 'self'; script-src 'hash-'")
        self.cspnonce = CSP("default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'")
        self.cspnonceincorrect = CSP("default-src 'self'; script-src 'nonce-'")
        self.cspempty = CSP("default-src 'self'")

    def test_policyHasScriptNonces(self):
        self.assertFalse(self.csphash.policyHasScriptNonces())
        self.assertFalse(self.cspempty.policyHasScriptNonces())
        self.assertTrue(self.cspnonce.policyHasScriptNonces())
        self.assertFalse(self.cspnonceincorrect.policyHasScriptNonces())

    def test_policyHasScriptHashes(self):
        self.assertTrue(self.csphash.policyHasScriptHashes())
        self.assertFalse(self.cspempty.policyHasScriptHashes())
        self.assertFalse(self.csphashincorrect.policyHasScriptHashes())
        self.assertFalse(self.cspnonce.policyHasScriptHashes())


    def test_isNonce(self):
        self.assertFalse(CSP.isNonce(None))
        self.assertTrue(CSP.isNonce("'nonce-4AEemGb0xJptoIGFP3Nd'"))
        self.assertFalse(CSP.isNonce("'4AEemGb0xJptoIGFP3Nd'"))
        self.assertFalse(CSP.isNonce("'nonce-'"))
        self.assertFalse(CSP.isNonce("nonce-4AEemGb0xJptoIGFP3Nd"))


    def test_isHash(self):
        self.assertFalse(CSP.isHash(None))
        self.assertTrue(CSP.isHash("'sha256-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw='"))
        self.assertTrue(CSP.isHash("'sha384-DI19sed4TRZkc5YyauS5puOZXwfWK81rccnt0+9Wzx1X+klUtK2qGbBrYLz9av3V'"))
        self.assertTrue(CSP.isHash("'sha512-5FG9ADHaHu4pIl9fFiPe/QSRZ1O8nPZ5T3JVmWTzQqXsscEJ1EB9qNO4OQWoPekESrpPp/vfXBTJeI4DImgM+g=='"))
        self.assertFalse(CSP.isHash("'koen-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw='"))
#        self.assertTrue(CSP.isHash("sha256-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw="))


class CSPMissingCheckerTest(unittest.TestCase):
    def setUp(self):
        self.x = CSPMissingChecker()

    def test_checkNoCSP(self):
        nocsp = dict()
        nocsp['test'] = 'value'
        result = self.x.check(nocsp)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)

    def test_none(self):
        nonecsp = None
        result = self.x.check(nonecsp)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)


    def test_NoneCsp(self):
        hascsp = dict()
        hascsp['content-security-policy'] = None
        self.assertEquals(self.x.check(hascsp), [])

    def test_CSPOK(self):
        hascsp2 = dict()
        hascsp2['content-security-policy'] = "default-src 'self'; script-src 'sha256-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw='"
        self.assertEquals(self.x.check(hascsp2), [])

class XPoweredByPresentCheckerTest(unittest.TestCase):
    def setUp(self):
        self.x = XPoweredByPresentChecker()

    def test_checkNoCSP(self):
        nox = dict()
        nox['test'] = 'value'
        self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
        nonex = None
        self.assertEquals(self.x.check(nonex), [])

    def test_NoneValue(self):
        hasx = dict()
        hasx['x-powered-by'] = None
        result = self.x.check(hasx)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)

    def test_ValidValue(self):
        hasx2 = dict()
        hasx2['x-powered-by'] = "Apache"
        result = self.x.check(hasx2)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)


class XFrameOptionsCheckerTest(unittest.TestCase):
    def setUp(self):
        self.x = XFrameOptionsGoodChecker()

    def test_checkNoCSP(self):
        xempty = dict()
        self.assertEquals(self.x.check(xempty), [])

    def test_checkNone(self):
        xnone = None
        self.assertEquals(self.x.check(xnone), [])

    def test_Good(self):
        xhas = dict()
        xhas['x-frame-options'] = 'deny'
        self.assertEquals(self.x.check(xhas), [])

    def test_Bad(self):
        xhasbad = dict()
        xhasbad['x-frame-options'] = 'allow-from google.com'
        result = self.x.check(xhasbad)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)

    def test_None(self):
        xhasNone = dict()
        xhasNone['x-frame-options'] = None
        result = self.x.check(xhasNone)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)


class NonceLengthTest(unittest.TestCase):

    def setUp(self):
        self.x = CSPNonceLengthChecker()

    def test_checkNoCSP(self):
        nox = dict()
        nox['test'] = 'value'
        self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
        nonex = None
        self.assertEquals(self.x.check(nonex), [])

    def test_NoneCSP(self):
        hasx = dict()
        hasx['content-security-policy'] = None
        self.assertEquals(self.x.check(hasx), [])

    def test_ShortNonce(self):
        hasx3 = dict()
        hasx3['content-security-policy'] = "script-src 'nonce-short'"
        result = self.x.check(hasx3)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)

    def test_ShortNonce2(self):
        hasx4 = dict()
        hasx4['content-security-policy'] = "default-src 'self'; script-src 'nonce-'"
        result = self.x.check(hasx4)
        self.assertIsNotNone(result)
        self.assertEquals(len(result), 1)

    def test_ValidNonce(self):
        hasx2 = dict()
        hasx2['content-security-policy'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
        self.assertEquals(self.x.check(hasx2), [])


class HTTPTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPSCRHTTPChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_NoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_HTTPURI(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       result = self.x.check(hasx3)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_HTTPSURI(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "report-uri https://foo.bar/csp"
       self.assertEquals(self.x.check(hasx4), [])

    def test_NoURI(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
       self.assertEquals(self.x.check(hasx2), [])

class DeprectedDirectiveTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPDeprecatedDirectiveChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_NonePolicy(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_DeprecatedReportUriCSP3(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       result = self.x.check(hasx3)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_ValidCSP(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
       self.assertEquals(self.x.check(hasx2), [])


class DepreEmptyPolicyTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPEmptyChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_NoneCsp(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       result = self.x.check(hasx)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_EmptyCsp(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = ''
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_NoneEmpty(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       self.assertEquals(self.x.check(hasx3), [])

    def test_NoneEmpty2(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'"
       self.assertEquals(self.x.check(hasx2), [])


class IPSourceTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPIPSourceChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_NoneCsp(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_IpSource(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = 'script-src 127.0.0.1'
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_IpSource2(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = 'script-src 200.200.200.200'
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_URI(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       self.assertEquals(self.x.check(hasx3), [])

    def test_URI2(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEquals(self.x.check(hasx2), [])

class MissingDirectiveTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPMissingDirectiveChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_AllMissing(self):
       hasx = dict()
       hasx['content-security-policy'] = ''
       result = self.x.check(hasx)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 4)#all

    def test_BaseURIMissing(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "default-src 'self'"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 2) #base-uri

    def test_ObjectSrcPresentOthersMissing(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = 'object-src 127.0.0.1'
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 3) #base-uri, script-src, default-src

    def test_ScriptSrcPresentOthersMissing(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "script-src 'none'"
       result = self.x.check(hasx3)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 3)#base-uri & object-src, default-src

    def test_AllPresent(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src tweakers.net; script-src tweakers.net; object-src tweakers.net; base-uri tweakers.net"
       self.assertEquals(self.x.check(hasx2), [])

    def test_DefaultSrcMissing(self):
       hasx6 = dict()
       hasx6['content-security-policy'] = "script-src tweakers.net; object-src tweakers.net; base-uri tweakers.net"
       result = self.x.check(hasx6)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)#default-src

    def test_AllMissing(self):
       hasx7 = dict()
       hasx7['content-security-policy'] = "child-src 'none';"
       result = self.x.check(hasx7)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 4) #All of them

    def test_BaseUriMissing(self):
       hasx8 = dict()
       hasx8['content-security-policy'] = "default-src 'none';"
       result = self.x.check(hasx8)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 2) #base-uri; others are done by default-src

    def test_ObjectSrcPresentOtherMissing(self):
       hasx10 = dict()
       hasx10['content-security-policy'] = "child-src 'none'; object-src 'none';"
       result = self.x.check(hasx10)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 3) #missing default-src, script-src, and base-uri directives

    def test_ScriptSrcPresentOtherMissing(self):
       hasx11 = dict()
       hasx11['content-security-policy'] = "child-src 'none'; script-src 'none';"
       result = self.x.check(hasx11)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 3) #missing default-src, object-src, and base-uri directives


class WildCardTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPWildCardChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_wildCard(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = 'script-src *'
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_NoWildCard(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = 'script-src 200.200.200.200'
       self.assertEquals(self.x.check(hasx4), [])

    def test_NoWildCard2(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "report-uri http://foo.bar/csp"
       self.assertEquals(self.x.check(hasx3), [])

    def test_NoWildCard3(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEquals(self.x.check(hasx2), [])

    def test_NoWildCard2(self):
       hasx6 = dict()
       hasx6['content-security-policy'] = "object-src *; script-src 'none';"
       result = self.x.check(hasx6)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_NoWildCardDefaultSrc(self):
       hasx7 = dict()
       hasx7['content-security-policy'] = "default-src *; script-src 'none';" #object-src inherits default-src and is thus insecure
       result = self.x.check(hasx7)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)


class UnsafeEvalTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPUnsafeEvalChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_wildCardOk(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = 'script-src *'
       self.assertEquals(self.x.check(hasx5), [])

    def test_UnsafeEvalNok(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "script-src 'unsafe-eval'"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_CSPOK(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEquals(self.x.check(hasx2), [])

    def test_UnsafeEvalNok2(self):
       hasx6 = dict()
       hasx6['content-security-policy'] = "default-src 'none'; script-src 'unsafe-eval';"
       result = self.x.check(hasx6)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_UnsafeEvalNok3(self):
       hasx7 = dict()
       hasx7['content-security-policy'] = "default-src 'none'; script-src 'unsafe-eval' 'unsafe-inline';"
       result = self.x.check(hasx7)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_UnsafeEvalDefaultSrcNok(self):
       hasx8 = dict()
       hasx8['content-security-policy'] = "default-src 'unsafe-eval';"
       result = self.x.check(hasx8)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_UnsafeEvalDefaultSrcNok2(self):
       hasx9 = dict()
       hasx9['content-security-policy'] = "default-src 'unsafe-eval' 'unsafe-inline';"
       result = self.x.check(hasx9)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)



class UnsafeInlineTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPUnsafeInlineChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_wildCardOk(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = 'script-src *'
       self.assertEquals(self.x.check(hasx5), [])

    def test_UnsafeInlineNok(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "script-src 'unsafe-inline'"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_CSP(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEquals(self.x.check(hasx2), [])

    def test_UnsafeInlineNok2(self):
       hasx6 = dict()
       hasx6['content-security-policy'] = "default-src 'none'; script-src 'unsafe-inline'; "
       result = self.x.check(hasx6)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_UnsafeInlineNok3(self):
       hasx7 = dict()
       hasx7['content-security-policy'] = "default-src 'none'; script-src 'unsafe-eval' 'unsafe-inline';"
       result = self.x.check(hasx7)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_UnsafeInlineWithDefaultSrc(self):
       hasx8 = dict()
       hasx8['content-security-policy'] = "default-src 'unsafe-inline';"
       result = self.x.check(hasx8)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_UnsafeInlineWithDefaultSrc2(self):
       hasx9 = dict()
       hasx9['content-security-policy'] = "default-src 'unsafe-eval' 'unsafe-inline';"
       result = self.x.check(hasx9)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)


class UnsafeUrkSchemeTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPPlainUrlSchemesChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])


    def test_All(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "script-src https: http: data:"
       self.assertIsNotNone(self.x.check(hasx4))
       self.assertEquals(len(self.x.check(hasx4)), 3) #all 3 of them

    def test_http(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "script-src http:"
       self.assertIsNotNone(self.x.check(hasx3))
       self.assertEquals(len(self.x.check(hasx3)), 1) #http:

    def test_validCSP(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEquals(self.x.check(hasx2), [])


class CSPScriptWhitelistBypassCheckerTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPScriptWhitelistBypassChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_ValidCSP(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "default-src 'none'; script-src buyens.org"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)
       self.assertEquals(result[0].severity, FindingSeverity.MEDIUM_MAYBE) #validate if the url does not have known bypasses

    def test_KnownBypass(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src https://gstatic.com/fsn/angular_js-bundle1.js"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)
       self.assertEquals(result[0].severity, FindingSeverity.HIGH) #known bypass

    def test_KnownSelf(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src 'self'"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)
       self.assertEquals(result[0].severity, FindingSeverity.MEDIUM_MAYBE)


class FlashWhitelistBypassCheckerTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPFlashObjectWhitelistBypassChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_ValidCSP(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "default-src 'none'; object-src buyens.org"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)
       self.assertEquals(result[0].severity, FindingSeverity.MEDIUM_MAYBE) #restrict to none if possible

    def test_KnownBypass(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; object-src ajax.googleapis.com"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)


class UnknownDirectiveCheckerTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPUnknownDirectiveChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_checkInvalidKeyword(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "koen 'none'; object-src ajax.googleapis.com"
       result = self.x.check(hasx2)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_checkKeywordWithColorn(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "object-src:; object-src ajax.googleapis.com"
       result = self.x.check(hasx3)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_checkValidCsp(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; object-src ajax.googleapis.com"
       self.assertEquals(self.x.check(hasx5), [])


class MissingColumnCheckerTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPMissingColumnChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
#       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
#       self.assertEquals(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
#       self.assertEquals(self.x.check(hasx), [])

    def test_checkInvalidKeyword(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "script-src foo.bar object-src 'none'"
       result = self.x.check(hasx2)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_checkValidCsp(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; object-src ajax.googleapis.com"
#       self.assertEquals(self.x.check(hasx5), [])

if __name__ == '__main__':
    unittest.main()
