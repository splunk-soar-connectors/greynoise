# File: greynoise_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# URLs
API_KEY_CHECK_URL = "https://api.greynoise.io/ping"
VISUALIZATION_URL = "https://www.greynoise.io/viz/ip/{ip}"

TRUST_LEVELS = {
    "1": "1 - Reasonably Ignore",
    "2": "2 - Commonly Seen"
}

ONPOLL_SIZE_CONFIG_PARAM = "'on_poll_size' config parameter"

# Integer validation constants
VALID_INTEGER_MSG = "Please provide a valid integer value in the {key}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {key}"

# exception handling
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

ERROR_MESSAGE = "Error occurred making API request"
INTERNAL_IP_ERROR_MESSAGE = "Error occured, IP is an internal IP"
API_PARSE_ERROR_MESSAGE = "Error occurred while processing API response"
