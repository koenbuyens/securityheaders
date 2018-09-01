import unittest
from securityheaders.checkers import XPoweredByPresentChecker

class XPoweredByPresentCheckerTest(unittest.TestCase):
    def setUp(self):
        self.x = XPoweredByPresentChecker()

    def test_checkNoCSP(self):
        nox = dict()
        nox['test'] = 'value'
        self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
        nonex = None
        self.assertEqual(self.x.check(nonex), [])

    def test_NoneValue(self):
        hasx = dict()
        hasx['x-powered-by'] = None
        result = self.x.check(hasx)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

    def test_ValidValue(self):
        hasx2 = dict()
        hasx2['x-powered-by'] = "Apache"
        result = self.x.check(hasx2)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

if __name__ == '__main__':
    unittest.main()
