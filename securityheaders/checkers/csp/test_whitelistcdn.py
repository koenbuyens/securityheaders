import unittest

from securityheaders.checkers import FindingSeverity
from securityheaders.checkers.csp import CSPScriptWhitelistCDNBypassChecker,CSPReportOnlyScriptWhitelistCDNBypassChecker

class CSPScriptWhitelistCDNBypassCheckerTest(unittest.TestCase):

    def setUp(self):
       self.x = CSPScriptWhitelistCDNBypassChecker()
       self.y = CSPReportOnlyScriptWhitelistCDNBypassChecker()
       self.options = dict()
       self.options['CSPScriptWhitelistCDNBypassChecker'] = dict()
       self.options['CSPScriptWhitelistCDNBypassChecker']['cdn'] = ['//*.gstatic.com/','//*.afxcdn.net']
       self.options['CSPReportOnlyScriptWhitelistCDNBypassChecker'] = dict()
       self.options['CSPReportOnlyScriptWhitelistCDNBypassChecker']['cdn'] = ['//*.gstatic.com/','//*.afxcdn.net']


    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_checkNoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEqual(self.x.check(hasx), [])

    def test_ValidCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = "default-src 'none'; script-src buyens.org"
       result = self.x.check(hasx)
       self.assertIsNotNone(result)
       self.assertEqual(self.x.check(hasx), [])

    def test_ValidCSP2(self):
       hasx = dict()
       hasx['content-security-policy'] = "default-src 'none'; script-src https://gstatic.com/script.js"
       result = self.x.check(hasx)
       self.assertIsNotNone(result)
       self.assertEqual(self.x.check(hasx), [])

    def test_ValidCSP3(self):
       hasx = dict()
       hasx['content-security-policy'] = "default-src 'none'; script-src https://afxcdn.net/myverylongscript.js"
       result = self.x.check(hasx)
       self.assertIsNotNone(result)
       self.assertEqual(self.x.check(hasx), [])

    def test_IncludeWholeCDN(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src https://gstatic.com"
       result = self.x.check(hasx5, self.options)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.HIGH) #known bypass

    def test_IncludeWholeCDN2(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src gstatic.com"
       result = self.x.check(hasx5, self.options)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.HIGH) #known bypass

    def test_IncludeWholeCDNWildcard(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src https://*.afxcdn.net"
       result = self.x.check(hasx5, self.options)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.HIGH) #known bypass

    def test_IncludeWholeCDNSubdomain(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src 'none'; script-src koen.afxcdn.net"
       result = self.x.check(hasx5, self.options)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
       self.assertEqual(result[0].severity, FindingSeverity.HIGH) #known bypass

if __name__ == '__main__':
    unittest.main()
