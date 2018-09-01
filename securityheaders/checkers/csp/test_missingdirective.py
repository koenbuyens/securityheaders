import unittest

from securityheaders.checkers.csp import CSPMissingDirectiveChecker, CSPReportOnlyMissingDirectiveChecker

class MissingDirectiveTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPMissingDirectiveChecker()
       self.y = CSPReportOnlyMissingDirectiveChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_AllMissing(self):
       hasx = dict()
       hasx['content-security-policy'] = ''
       result = self.x.check(hasx)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 4)#all

    def test_BaseURIMissing(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "default-src 'self'"
       result = self.x.check(hasx4)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 2) #base-uri

    def test_ObjectSrcPresentOthersMissing(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = 'object-src 127.0.0.1'
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 3) #base-uri, script-src, default-src

    def test_ScriptSrcPresentOthersMissing(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "script-src 'none'"
       result = self.x.check(hasx3)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 3)#base-uri & object-src, default-src

    def test_AllPresent(self):
       hasx2 = dict()
       hasx2['content-security-policy'] = "default-src tweakers.net; script-src tweakers.net; object-src tweakers.net; base-uri tweakers.net"
       self.assertEqual(self.x.check(hasx2), [])

    def test_DefaultSrcMissing(self):
       hasx6 = dict()
       hasx6['content-security-policy'] = "script-src tweakers.net; object-src tweakers.net; base-uri tweakers.net"
       result = self.x.check(hasx6)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)#default-src

    def test_AllMissing(self):
       hasx7 = dict()
       hasx7['content-security-policy'] = "child-src 'none';"
       result = self.x.check(hasx7)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 4) #All of them

    def test_BaseUriMissing(self):
       hasx8 = dict()
       hasx8['content-security-policy'] = "default-src 'none';"
       result = self.x.check(hasx8)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 2) #base-uri; others are done by default-src

    def test_ObjectSrcPresentOtherMissingRO(self):
        hasx10 = dict()
        hasx10['content-security-policy-report-only'] = "child-src 'none'; object-src 'none';"
        result = self.y.check(hasx10)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 3) #missing default-src, script-src, and base-uri directives

    def test_ScriptSrcPresentOtherMissingRO(self):
        hasx11 = dict()
        hasx11['content-security-policy-report-only'] = "child-src 'none'; script-src 'none';"
        result = self.y.check(hasx11)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 3) #missing default-src, object-src, and base-uri directives

    def test_ObjectSrcPresentOtherMissing(self):
       hasx10 = dict()
       hasx10['content-security-policy'] = "child-src 'none'; object-src 'none';"
       result = self.x.check(hasx10)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 3) #missing default-src, script-src, and base-uri directives

    def test_ScriptSrcPresentOtherMissing(self):
       hasx11 = dict()
       hasx11['content-security-policy'] = "child-src 'none'; script-src 'none';"
       result = self.x.check(hasx11)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 3) #missing default-src, object-src, and base-uri directives

if __name__ == '__main__':
    unittest.main()
