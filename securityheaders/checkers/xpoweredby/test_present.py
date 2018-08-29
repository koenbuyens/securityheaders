import unittest
from present import XPoweredByPresentChecker

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

if __name__ == '__main__':
    unittest.main()
