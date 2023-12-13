import unittest
from shieldsentry.shieldsentry import ShieldSentry
from time import sleep

class ColoredTestResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        self.stream.write('\033[92m')  # Set the text to green
        self.stream.write('PASS ')
        self.stream.write(self.getDescription(test))
        self.stream.write('\033[0m\n')  # Reset to default color

    def addError(self, test, err):
        super().addError(test, err)
        self.stream.write('\033[91m')  # Set the text to red
        self.stream.write('ERROR ')
        self.stream.write(self.getDescription(test))
        self.stream.write('\033[0m\n')  # Reset to default color

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.stream.write('\033[93m')  # Set the text to yellow
        self.stream.write('FAIL ')
        self.stream.write(self.getDescription(test))
        self.stream.write('\033[0m\n')  # Reset to default color

class ColoredTestRunner(unittest.TextTestRunner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, resultclass=ColoredTestResult, **kwargs)

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

    def test_access_control(self):
        # Test cases for access control
        self.assertTrue(self.input_handler.has_permission('admin', 'write'), "Admin should have write permission")
        self.assertTrue(self.input_handler.has_permission('user', 'read'), "User should have read permission")
        self.assertFalse(self.input_handler.has_permission('guest', 'write'), "Guest should not have write permission")
        self.assertFalse(self.input_handler.has_permission('invalid_role', 'read'), "Invalid role should not have any permission")

    def test_rate_limiting_and_quota(self):
        user_id = 'test_user'

        # Assuming maxRequestsPerMinute is set to 60
        for _ in range(60):
            self.assertFalse(self.input_handler.is_rate_limited(user_id), "User should not be rate limited yet")

        # The next request should be rate limited
        self.assertTrue(self.input_handler.is_rate_limited(user_id), "User should be rate limited")

        # Wait for the rate limit window to pass
        sleep(60)  # Wait for 1 minute

        # User should be able to make requests again, but quota might still apply
        self.assertFalse(self.input_handler.is_rate_limited(user_id), "User should not be rate limited after waiting")

        # Testing quota exceeding
        for _ in range(940):  # Making a total of 1000 requests
            self.input_handler.is_rate_limited(user_id)

        # The next request should exceed quota
        self.assertTrue(self.input_handler.is_rate_limited(user_id), "User should have exceeded quota")

if __name__ == '__main__':
    unittest.main(testRunner=ColoredTestRunner)
