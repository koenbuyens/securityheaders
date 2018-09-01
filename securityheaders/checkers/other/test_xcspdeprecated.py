import unittest

from securityheaders.checkers.other import XCSPDeprecatedChecker

class XCSPDeprecatedCheckerTest(unittest.TestCase):
    def setUp(self):
       self.x = XCSPDeprecatedChecker()

    def test_checkNoHeader(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_checkNone2(self):
       hasx = dict()
       hasx['x-content-security-policy'] = None
       result = self.x.check(hasx)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_checkValid(self):
       hasx5 = dict()
       hasx5['x-content-security-policy'] = "default-src: 'none'"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_checkOther(self):
       hasx5 = dict()
       hasx5['content-security-policy'] = "default-src: 'none'"
       self.assertEqual(self.x.check(hasx5), [])

if __name__ == '__main__':
    unittest.main()
