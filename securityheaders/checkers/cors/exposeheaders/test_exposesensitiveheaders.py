import unittest

from securityheaders.checkers.cors import AccessControlExposeHeadersSensitiveChecker

class AccessControlExposeHeadersSensitiveCheckerTest(unittest.TestCase):
    def setUp(self):
       self.x = AccessControlExposeHeadersSensitiveChecker()

    def test_checkNoHeader(self):
       nox = dict()
       nox['test'] = 'value'
       self.assertEqual(self.x.check(nox), [])

    def test_checkNone(self):
       nonex = None
       self.assertEqual(self.x.check(nonex), [])

    def test_checkNone2(self):
       hasx = dict()
       hasx['access-control-expose-headers'] = None
       self.assertEqual(self.x.check(hasx), [])

    def test_checkInvalid(self):
       hasx2 = dict()
       hasx2['access-control-expose-headers'] = "Authentication-Token"
       result = self.x.check(hasx2)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_checkInvalid2(self):
       hasx5 = dict()
       hasx5['access-control-expose-headers'] = "Authorization"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_checkInvalid3(self):
       hasx5 = dict()
       hasx5['access-control-expose-headers'] = "Session"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 1)

    def test_checkInvalid4(self):
       hasx5 = dict()
       hasx5['access-control-expose-headers'] = "Session, Authentication-Token, PUT"
       result = self.x.check(hasx5)
       self.assertIsNotNone(result)
       self.assertEqual(len(result), 2)

    def test_checkValid2(self):
       hasx5 = dict()
       hasx5['access-control-expose-headers'] = "PUT"
       self.assertEqual(self.x.check(hasx5), [])

if __name__ == '__main__':
    unittest.main()
