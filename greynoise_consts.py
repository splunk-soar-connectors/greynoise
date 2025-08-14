# File: greynoise_consts.py
#
# Copyright (c) GreyNoise, 2019-2025
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

TRUST_LEVELS = {"1": "1 - Reasonably Ignore", "2": "2 - Commonly Seen"}

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
    "Resetting the state file with the default format. Please try again."
)
SEVERITY_MAP = {"malicious": "high", "suspicious": "medium", "benign": "low"}

DEFAULT_SIZE_FOR_ON_POLL = 25

# Constants for webhook
CONTENT_TYPE_HEADER = ["Content-Type", "application/json"]
GREYNOISE_FEED_IP_EVENT_TYPE = "ip-classification-change"
GREYNOISE_FEED_CVE_EVENT_TYPE = "cve-status-change"
GREYNOISE_ALERT_TAG = "greynoise-alert"
GREYNOISE_FEED_TAG = "greynoise-feed"
GREYNOISE_FEED_CVE_TAG = "greynoise-feed-cve"
GREYNOISE_FEED_IP_TAG = "greynoise-feed-ip"

# Response status codes for webhook
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_METHOD_NOT_ALLOWED = 405
DEFAULT_SIZE_FOR_GNQL_QUERY = 100
PAGINATOR_MAX_SIZE = 1000

TIMELINE_VALUE_LIST = [
    "classification",
    "source_org",
    "source_asn",
    "source_rdns",
    "http_path",
    "http_user_agent",
    "destination_port",
    "tag_ids",
]

LOOKUP_IP_SUCCESS_MESSAGE = "Lookup IP action successfully completed"
IP_REPUTATION_SUCCESS_MESSAGE = "IP Reputation action successfully completed"
LOOKUP_IPS_SUCCESS_MESSAGE = "Lookup IPs action successfully completed"
TEST_CONNECTIVITY_SUCCESS_MESSAGE = "Test Connectivity Passed"
GET_CVE_DETAILS_SUCCESS_MESSAGE = "Get CVE Details action successfully completed"
GNQL_QUERY_SUCCESS_MESSAGE = "GNQL Query action successfully completed"
NOISE_IP_TIMELINE_SUCCESS_MESSAGE = "Noise IP Timeline action successfully completed"
ON_POLL_DEFAULT_QUERY_ERROR_MESSAGE = "Default on poll query unchanged, please enter a valid GNQL query"
NO_DATA_FOUND_MESSAGE = "No Data Found"
