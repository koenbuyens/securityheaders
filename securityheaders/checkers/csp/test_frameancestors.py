
import unittest

from securityheaders.checkers.csp import CSPFrameAncestorsChecker, CSPReportOnlyFrameAncestorsChecker

class HTTPTest(unittest.TestCase):
    def setUp(self):
       self.x = CSPFrameAncestorsChecker()
       self.y = CSPReportOnlyFrameAncestorsChecker()

    def test_checkNoCSP(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_NoneCSP(self):
       hasx = dict()
       hasx['content-security-policy'] = None
       self.assertEqual(self.x.check(hasx), [])

    def test_FrameSrc(self):
       hasx3 = dict()
       hasx3['content-security-policy'] = "frame-ancestors https://foo.bar"
       result = self.x.check(hasx3)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_Good(self):
       hasx4 = dict()
       hasx4['content-security-policy'] = "frame-ancestors 'self'"
       self.assertEqual(self.x.check(hasx4), [])
    
    def test_Good2(self):
        hasx3 = dict()
        hasx3['content-security-policy'] = "frame-ancestors 'none'"
        self.assertEqual(self.x.check(hasx3), [])
    
    def test_Bad2(self):
        hasx4 = dict()
        hasx4['content-security-policy'] = "frame-ancestors *.tweakers.net *.tweakimg.net"
        result = self.x.check(hasx4)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)


    def test_Good2RO(self):
        hasx3 = dict()
        hasx3['content-security-policy-report-only'] = "frame-ancestors 'none'"
        self.assertEqual(self.y.check(hasx3), [])
    
    def test_Bad2RO(self):
        hasx4 = dict()
        hasx4['content-security-policy-report-only'] = "frame-ancestors *.tweakers.net *.tweakimg.net"
        result = self.y.check(hasx4)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)

if __name__ == '__main__':
    unittest.main()
