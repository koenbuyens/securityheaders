import unittest

from securityheaders.checkers.cors import AccessControlAllowOriginNullChecker

class AccessControlAllowOriginNullCheckerTest(unittest.TestCase):
    def setUp(self):
       self.x = AccessControlAllowOriginNullChecker()

    def test_checkNoHeader(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEquals(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEquals(self.x.check(nonex), [])

    def test_checkNone2(self):
       hasx = dict()
       hasx['access-control-allow-origin'] = None
       self.assertEquals(self.x.check(hasx), [])

    def test_checkInvalid(self):
       hasx2 = dict()
       hasx2['access-control-allow-origin'] = "null"
       result = self.x.check(hasx2)
       self.assertIsNotNone(result)
       self.assertEquals(len(result), 1)

    def test_checkValid(self):
       hasx5 = dict()
       hasx5['access-control-allow-origin'] = "https://www.google.com, https://www.facebook.com"
       self.assertEquals(self.x.check(hasx5), [])

if __name__ == '__main__':
    unittest.main()
