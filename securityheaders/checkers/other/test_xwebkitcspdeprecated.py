import unittest

from securityheaders.checkers.other import XWebKitCSPDeprecatedChecker

class XWebKitCSPDeprecatedCheckerTest(unittest.TestCase):
    def setUp(self):
       self.x = XWebKitCSPDeprecatedChecker()

    def test_checkNoHeader(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNone2(self):
       hasx = dict()
       hasx['x-webkit-csp'] = None
       result = self.x.check(hasx)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_checkValid(self):
       hasx5 = dict()
       hasx5['x-webkit-csp'] = "default-src: 'none'"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_checkOther(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src: 'none'"
       self.assertEquals(self.x.check(hasx5), [])

if __name__ == '__main__':
    unittest.main()
