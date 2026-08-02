# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import unittest

from greynoise_webhook_auth import is_webhook_authenticated


class WebhookAuthenticationTests(unittest.TestCase):
    def test_accepts_matching_token_case_insensitively(self):
        self.assertTrue(is_webhook_authenticated({"X-GreyNoise-Token": "expected"}, "expected"))
        self.assertTrue(is_webhook_authenticated({"x-greynoise-token": "expected"}, "expected"))

    def test_fails_closed_for_missing_or_invalid_configuration(self):
        self.assertFalse(is_webhook_authenticated({}, "expected"))
        self.assertFalse(is_webhook_authenticated({"X-GreyNoise-Token": "wrong"}, "expected"))
        self.assertFalse(is_webhook_authenticated({"X-GreyNoise-Token": "expected"}, ""))
        self.assertFalse(is_webhook_authenticated({"X-GreyNoise-Token": "expected"}, None))


if __name__ == "__main__":
    unittest.main()
