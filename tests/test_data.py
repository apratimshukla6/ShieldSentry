import unittest
from shieldsentry.shieldsentry import ShieldSentry

class TestShieldSentry(unittest.TestCase):
    def setUp(self):
        # This method will be run before each test
        self.input_handler = ShieldSentry()

    def test_sql_injection_sanitization(self):
        sql_input = "\" OR \"1\"=\"1"
        sanitized_sql_input = self.input_handler.sanitize('SQL', sql_input)
        expected_output = "\\\" OR \\\"1\\\"=\\\"1"  # Expected to escape double quotes and equals
        self.assertEqual(sanitized_sql_input, expected_output, "SQL sanitization failed")

    def test_xss_sanitization(self):
        xss_input = "<script>alert('XSS')</script>"
        sanitized_xss_input = self.input_handler.sanitize('HTML', xss_input)
        expected_output = "&amp;lt;script&amp;gt;alert(&#x27;XSS&#x27;)&amp;lt;&#x2F;script&amp;gt;"  # Expected to escape HTML
        self.assertEqual(sanitized_xss_input, expected_output, "XSS sanitization failed")

if __name__ == '__main__':
    unittest.main()
