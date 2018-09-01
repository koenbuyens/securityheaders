import unittest

from securityheaders.checkers.csp import CSPUnsafeEvalChecker, CSPReportOnlyUnsafeEvalChecker

class UnsafeEvalTest(unittest.TestCase):
    def setUp(self):
        self.x = CSPUnsafeEvalChecker()
        self.y = CSPReportOnlyUnsafeEvalChecker()

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

    def test_UnsafeEvalNok(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "script-src 'unsafe-eval'"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_CSPOK(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src 'self'; script-src tweakers.net"
       self.assertEqual(self.x.check(hasx2), [])

    def test_UnsafeEvalNokRO(self):
        hasx4 = dict()
        hasx4['content-security-policy-report-only'] = "script-src 'unsafe-eval'"
        result = self.y.check(hasx4)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
    
    def test_CSPOKRO(self):
        hasx2 = dict()
        hasx2['content-security-policy-report-only'] = "default-src 'self'; script-src tweakers.net"
        self.assertEqual(self.y.check(hasx2), [])

    def test_UnsafeEvalNok2(self):
       hasx6 = dict()
       hasx6['content-security-policy'] = "default-src 'none'; script-src 'unsafe-eval';"
       result = self.x.check(hasx6)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_UnsafeEvalNok3(self):
       hasx7 = dict()
       hasx7['content-security-policy'] = "default-src 'none'; script-src 'unsafe-eval' 'unsafe-inline';"
       result = self.x.check(hasx7)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_UnsafeEvalDefaultSrcNok(self):
       hasx8 = dict()
       hasx8['content-security-policy'] = "default-src 'unsafe-eval';"
       result = self.x.check(hasx8)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_UnsafeEvalDefaultSrcNok2(self):
       hasx9 = dict()
       hasx9['content-security-policy'] = "default-src 'unsafe-eval' 'unsafe-inline';"
       result = self.x.check(hasx9)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)


if __name__ == '__main__':
    unittest.main()
