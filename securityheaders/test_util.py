import unittest
try:
    from urlparse import urlparse
except ModuleNotFoundError:
    from urllib.parse import urlparse #python3

from securityheaders import Util

class UtilTest(unittest.TestCase):
    def test_isUrlSchemeNone(self):
        self.assertFalse(Util.isUrlScheme(None))

    def test_isUrlSchemeHttp(self):
        self.assertTrue(Util.isUrlScheme('http:'))

    def test_isUrlSchemeHttps(self):
        self.assertTrue(Util.isUrlScheme('https:'))

    def test_isUrlSchemeInvalid(self):
        self.assertFalse(Util.isUrlScheme('noscheme'))
        
    def test_getSchemeFreeUrlValid(self):
        self.assertEqual(Util.getSchemeFreeUrl('http://www.synopsys.com'), 'www.synopsys.com')

    def test_getSchemeFreeUrlCapitals(self):
        self.assertEqual(Util.getSchemeFreeUrl('HTTPS://www.synopsys.com'), 'www.synopsys.com')

    def test_getSchemeFreeUrlNone(self):
        self.assertEqual(Util.getSchemeFreeUrl(None), None)

    def test_matchWildcardUrls(self):
        urls = [
        '//vk.com/swf/video.swf',
        '//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'

        ]
        self.assertEqual(Util.matchWildcardUrls('https://*.vk.com', urls), None)
        self.assertEqual(Util.matchWildcardUrls('https://ajax.googleapis.com', urls), urlparse('//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'))
        self.assertEqual(Util.matchWildcardUrls('https://*.googleapis.com', urls), urlparse('//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'))
        self.assertEqual(Util.matchWildcardUrls(None, urls), None)
        self.assertEqual(Util.matchWildcardUrls('https://*.googleapis.com', None), None)
        self.assertEqual(Util.matchWildcardUrls('https://*.googleapis.com', []), None)
        self.assertEqual(Util.matchWildcardUrls('*.googleapis.com', urls), urlparse('//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf'))


if __name__ == '__main__':
    unittest.main()
