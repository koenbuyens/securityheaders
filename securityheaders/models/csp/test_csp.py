from securityheaders.models.csp import CSP
import unittest

class CSPTest(unittest.TestCase):
    def setUp(self):
        self.csphash = CSP("default-src 'self'; script-src 'sha256-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw='")
        self.csphashincorrect = CSP("default-src 'self'; script-src 'hash-'")
        self.cspnonce = CSP("default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'")
        self.cspnonceincorrect = CSP("default-src 'self'; script-src 'nonce-'")
        self.cspempty = CSP("default-src 'self'")

        self.csphashcamel = CSP("defaultSrc 'self'; scriptSrc 'sha256-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw='")
        self.csphashincorrectcamel = CSP("defaultSrc 'self'; scriptSrc 'hash-'")
        self.cspnoncecamel = CSP("defaultSrc 'self'; scriptSrc 'nonce-4AEemGb0xJptoIGFP3Nd'")
        self.cspnonceincorrectcamel = CSP("DefaultSrc 'self'; scriptSrc 'nonce-'")
        self.cspemptycamel = CSP("DefaultSrc 'self'")

    def test_policyHasScriptNonces(self):
        self.assertFalse(self.csphash.policyHasScriptNonces())
        self.assertFalse(self.csphashcamel.policyHasScriptNonces())
        self.assertFalse(self.cspempty.policyHasScriptNonces())
        self.assertFalse(self.cspemptycamel.policyHasScriptNonces())
        self.assertTrue(self.cspnonce.policyHasScriptNonces())
        self.assertTrue(self.cspnoncecamel.policyHasScriptNonces())
        self.assertFalse(self.cspnonceincorrect.policyHasScriptNonces())
        self.assertFalse(self.cspnonceincorrectcamel.policyHasScriptNonces())

    def test_policyHasScriptHashes(self):
        self.assertTrue(self.csphash.policyHasScriptHashes())
        self.assertTrue(self.csphashcamel.policyHasScriptHashes())
        self.assertFalse(self.cspempty.policyHasScriptHashes())
        self.assertFalse(self.csphashincorrect.policyHasScriptHashes())
        self.assertFalse(self.cspnonce.policyHasScriptHashes())
        self.assertFalse(self.cspemptycamel.policyHasScriptHashes())
        self.assertFalse(self.csphashincorrectcamel.policyHasScriptHashes())
        self.assertFalse(self.cspnoncecamel.policyHasScriptHashes())

    def test_isNonce(self):
        self.assertFalse(CSP.isNonce(None))
        self.assertTrue(CSP.isNonce("'nonce-4AEemGb0xJptoIGFP3Nd'"))
        self.assertFalse(CSP.isNonce("'4AEemGb0xJptoIGFP3Nd'"))
        self.assertFalse(CSP.isNonce("'nonce-'"))
        self.assertFalse(CSP.isNonce("nonce-4AEemGb0xJptoIGFP3Nd"))


    def test_isHash(self):
        self.assertFalse(CSP.isHash(None))
        self.assertTrue(CSP.isHash("'sha256-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw='"))
        self.assertTrue(CSP.isHash("'sha384-DI19sed4TRZkc5YyauS5puOZXwfWK81rccnt0+9Wzx1X+klUtK2qGbBrYLz9av3V'"))
        self.assertTrue(CSP.isHash("'sha512-5FG9ADHaHu4pIl9fFiPe/QSRZ1O8nPZ5T3JVmWTzQqXsscEJ1EB9qNO4OQWoPekESrpPp/vfXBTJeI4DImgM+g=='"))
        self.assertFalse(CSP.isHash("'koen-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw='"))
#        self.assertTrue(CSP.isHash("sha256-blLDIhKaPEZDhc4WD45BC7pZxW4WBRp7E5Ne1wC/vdw="))

if __name__ == '__main__':
    unittest.main()
