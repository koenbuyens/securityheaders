import unittest

from securityheaders.checkers.csp import CSPUnsafeInlineChecker, CSPReportOnlyUnsafeInlineChecker

class UnsafeInlineTest(unittest.TestCase):
    def setUp(self):
        self.x = CSPUnsafeInlineChecker()
        self.y = CSPReportOnlyUnsafeInlineChecker()


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

    def test_wildCardOk(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = 'script-src *'
       self.assertEqual(self.x.check(hasx5), [])

    def test_UnsafeInlineNok(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "script-src 'unsafe-inline'"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_CSP(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEqual(self.x.check(hasx2), [])

    def test_UnsafeInlineNok2(self):
       hasx6 = dict()
       hasx6['content-security-policy'] = "default-src 'none'; script-src 'unsafe-inline'; "
       result = self.x.check(hasx6)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)
    
    def test_CSPro(self):
        hasx2 = dict()
        hasx2['content-security-policy-report-only'] = "default-src 'self'; script-src tweakers.net"
        self.assertEqual(self.y.check(hasx2), [])

    def test_UnsafeInlineNok2ro(self):
        hasx6 = dict()
        hasx6['content-security-policy-report-only'] = "default-src 'none'; script-src 'unsafe-inline'; "
        result = self.y.check(hasx6)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

    def test_UnsafeInlineNok3(self):
       hasx7 = dict()
       hasx7['content-security-policy'] = "default-src 'none'; script-src 'unsafe-eval' 'unsafe-inline';"
       result = self.x.check(hasx7)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_UnsafeInlineWithDefaultSrc(self):
       hasx8 = dict()
       hasx8['content-security-policy'] = "default-src 'unsafe-inline';"
       result = self.x.check(hasx8)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_UnsafeInlineWithDefaultSrc2(self):
       hasx9 = dict()
       hasx9['content-security-policy'] = "default-src 'unsafe-eval' 'unsafe-inline';"
       result = self.x.check(hasx9)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

if __name__ == '__main__':
    unittest.main()
