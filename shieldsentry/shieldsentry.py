import os
import json
import re
from datetime import datetime, timedelta

class ShieldSentry:
    def __init__(self, specification="specifications.json"):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        specifications_path = os.path.join(current_dir, specification)
        with open(specifications_path, 'r') as file:
            self.specification = json.load(file)

        # Initialize access control settings
        self.roles = self.specification["accessControl"]["roles"]
        self.permissions = self.specification["accessControl"]["permissions"]
        self.rate_limiting = self.specification.get('apiRateLimiting', {})
        self.request_counters = {}

    def validate(self, input_type, value):
        rules = self.specification['inputTypes'][input_type]
        # Implementing basic validation logic
        if 'maxLength' in rules and len(value) > rules['maxLength']:
            return False
        if 'regex' in rules and not re.match(rules['regex'], value):
            return False
        if input_type == 'numeric':
            if (value < rules['min']) or (value > rules['max']):
                return False
        return True

    def html_escape(self, value):
        escape_chars = self.specification['sanitization']['HTML']['escapeCharacters']
        for char, escaped_char in escape_chars.items():
            value = value.replace(char, escaped_char)
        return value

    def sql_escape(self, value):
        escape_chars = self.specification['sanitization']['SQL']['escapeCharacters']
        for char, escaped_char in escape_chars.items():
            value = value.replace(char, escaped_char)
        return value

    def sanitize(self, context, value):
        if context == 'HTML':
            return self.html_escape(value)
        elif context == 'SQL':
            return self.sql_escape(value)
        else:
            # Default or unknown context: return value as is
            return value

    def handle_error(self, error_type):
        error = self.specification['errors'][error_type]
        print(f"Error {error['code']}: {error['message']}")

    def has_permission(self, user_role, action):
        """
        Check if a user role has permission to perform an action.
        """
        if user_role not in self.roles:
            return False

        allowed_actions = self.permissions.get(user_role, [])
        if "all" in allowed_actions or action in allowed_actions:
            return True

        return False
    
    def is_rate_limited(self, user_id):
        """ Check if a user has exceeded the rate limit or quota. """
        max_requests = self.rate_limiting.get('maxRequestsPerMinute', 60)
        quota = self.rate_limiting.get('quotaThreshold', 1000)

        # Initialize or reset counter
        if user_id not in self.request_counters or self.request_counters[user_id]['reset_time'] < datetime.now():
            self.request_counters[user_id] = {
                'request_count': 0,
                'quota_used': 0,
                'reset_time': datetime.now() + timedelta(minutes=1)
            }

        counter = self.request_counters[user_id]

        # Check quota
        if counter['quota_used'] >= quota:
            return True

        # Check rate limit
        if counter['request_count'] >= max_requests:
            return True

        # Increment counters
        counter['request_count'] += 1
        counter['quota_used'] += 1

        return False