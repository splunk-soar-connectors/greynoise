# File: greynoise_webhook_auth.py
#
# Copyright (c) GreyNoise, 2019-2026
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import hmac


GREYNOISE_TOKEN_HEADER = "x-greynoise-token"


def is_webhook_authenticated(headers, expected_secret):
    """Validate the caller-supplied GreyNoise webhook bearer token."""
    if not isinstance(headers, dict) or not isinstance(expected_secret, str) or not expected_secret:
        return False

    normalized_headers = {str(key).lower(): value for key, value in headers.items()}
    presented_secret = normalized_headers.get(GREYNOISE_TOKEN_HEADER)
    return isinstance(presented_secret, str) and hmac.compare_digest(presented_secret, expected_secret)
