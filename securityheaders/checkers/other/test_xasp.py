import unittest

from securityheaders.checkers.other import XASPNetPresentChecker

class XASPNetPresentCheckerTest(unittest.TestCase):
    def setUp(self):
       self.x = XASPNetPresentChecker()

    def test_checkNoHeader(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_checkNone2(self):
       hasx = dict()
       hasx['x-aspnet-version'] = None
       result = self.x.check(hasx)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_checkValid(self):
       hasx5 = dict()
       hasx5['x-aspnet-version'] = "2.0.50727"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

def test_checkNone3(self):
    hasx = dict()
    hasx['x-aspnetmvc-version'] = None
    result = self.x.check(hasx)
    self.assertIsNotNone(result)
    self.assertEqual(len(result), 1)
    
    def test_checkValid2(self):
        hasx5 = dict()
        hasx5['X-AspNetMvc-Version'] = "3.0"
        result = self.x.check(hasx5)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)


if __name__ == '__main__':
    unittest.main()
