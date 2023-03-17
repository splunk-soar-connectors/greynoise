# File: greynoise_consts.py
#
# Copyright (c) GreyNoise, 2019-2022.
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
# and limitations under the License.)

# URLs
API_KEY_CHECK_URL = "https://api.greynoise.io/ping"  # pragma: allowlist secret
VISUALIZATION_URL = "https://viz.greynoise.io/ip/{ip}"
GREYNOISE_ACTION_HANDLER_MESSAGE = "In action handler for: {identifier}"
GREYNOISE_ERROR_INVALID_FIELDS = "Please provide a valid value in the '{field}' parameter"
GREYNOISE_ERROR_INVALID_IP = "Validation failed for IP '{ip}'"

TRUST_LEVELS = {
    "1": "1 - Reasonably Ignore",
    "2": "2 - Commonly Seen"
}

ONPOLL_SIZE_CONFIG_PARAM = "'on_poll_size' config parameter"
SIZE_ACTION_PARAM = "'size' action parameter"
GREYNOISE_DEFAULT_TIMEOUT = 30

# Integer validation constants
VALID_INTEGER_MESSAGE = "Please provide a valid integer value in the {key}"
NON_NEGATIVE_INTEGER_MESSAGE = "Please provide a valid non-negative integer value in the {key}"
NON_NEG_NON_ZERO_INT_MESSAGE = "Please provide a valid non-zero positive integer value in the {key}"

# exception handling
ERROR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"

ERROR_MESSAGE = "Error occurred making API request"
INTERNAL_IP_ERROR_MESSAGE = "Error occurred, IP is an internal IP"
API_PARSE_ERROR_MESSAGE = "Error occurred while processing API response"

GREYNOISE_STATE_FILE_CORRUPT_ERROR = (
    "Error occurred while loading the state file due to its unexpected format. "
    "Resetting the state file with the default format. Please try again.")
