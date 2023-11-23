from shieldsentry.shieldsentry import ShieldSentry

# Assuming the SecureInputHandler class and specification JSON are properly set up

# Create an instance of the handler
input_handler = ShieldSentry()

# SQL Injection Test
sql_input = "\" OR \"1\"=\"1"
sanitized_sql_input = input_handler.sanitize('SQL', sql_input)
print("Original SQLi Input:", sql_input)
print("Sanitized SQLi Input:", sanitized_sql_input)

# XSS Test
xss_input = "<script>alert('XSS')</script>"
sanitized_xss_input = input_handler.sanitize('HTML', xss_input)
print("Original XSS Input:", xss_input)
print("Sanitized XSS Input:", sanitized_xss_input)
