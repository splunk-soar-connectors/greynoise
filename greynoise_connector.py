# File: greynoise_connector.py
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
# and limitations under the License.

# Python 3 Compatibility imports

import ipaddress
import json
import sys
import urllib.parse

# Phantom App imports
import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from six.moves.urllib.parse import urljoin as _urljoin

from greynoise.api import APIConfig, GreyNoise
from greynoise_consts import *


def urljoin(base, url):
    return _urljoin("{}/".format(base.rstrip("/")), url.lstrip("/"))


class GreyNoiseConnector(BaseConnector):
    """Connector for GreyNoise App."""

    def __init__(self):
        """GreyNoise App Constructor."""
        super().__init__()
        self._session = None
        self._app_version = None
        self._api_key = None
        self._integration_name = f"splunk-soar-v{self.get_app_json().get('app_version')}"

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.

        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_message = ERROR_MESSAGE_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except:
            pass

        if not error_code:
            error_text = f"Error Message: {error_message}"
        else:
            error_text = f"Error Code: {error_code}. Error Message: {error_message}"

        return error_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return (
                        action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MESSAGE.format(key=key)),
                        None,
                    )

                parameter = int(parameter)
            except Exception:
                return (
                    action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MESSAGE.format(key=key)),
                    None,
                )
            if parameter < 0:
                return (
                    action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MESSAGE.format(key=key)),
                    None,
                )
            if not allow_zero and parameter == 0:
                return (action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MESSAGE.format(key=key)), None)

        return phantom.APP_SUCCESS, parameter

    def _validate_comma_separated_ips(self, action_result, field, key):
        """
        Validate the comma separated ips. This method operates in 4 steps:
        1. Get list with comma as the seperator.
        2. Filter empty values from the list.
        3. Validate the non-empty IP values.
        4. Re-create the string with non-empty values.

        :param action_result: Action result object
        :param field: input field
        :param key: input parameter message key
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, filtered string or None in case of failure
        """
        if field:
            fields_list = field.split(",")
            filtered_fields_list = []
            for value in fields_list:
                value = value.strip()
                if value:
                    if not self._is_valid_ip(value):
                        error_message = f"{GREYNOISE_ERROR_INVALID_IP.format(ip=value)}. {GREYNOISE_ERROR_INVALID_FIELDS.format(field=key)}"
                        return action_result.set_status(phantom.APP_ERROR, error_message), None
                    filtered_fields_list.append(value)

            if not filtered_fields_list:
                return action_result.set_status(phantom.APP_ERROR, GREYNOISE_ERROR_INVALID_FIELDS.format(field=key)), None
            return phantom.APP_SUCCESS, ",".join(filtered_fields_list)
        return phantom.APP_SUCCESS, field

    def _is_valid_ip(self, input_ip_address):
        """
        Function that checks given address and returns True if the address is a valid IP address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        # If interface is present in the IP, it will be separated by the %
        if "%" in input_ip_address:
            ip_address_input = input_ip_address.split("%")[0]

        try:
            ipaddress.ip_address(ip_address_input)
        except Exception:
            return False

        return True

    def _validate_timeline_field(self, field, action_result):
        """
        Validate that the field parameter for timeline API is one of the allowed values.

        Args:
            field: The field parameter to validate
            action_result: The action result object to set status on if validation fails

        Returns:
            bool: True if validation passes, False otherwise
        """

        if field not in TIMELINE_VALUE_LIST:
            action_result.set_status(phantom.APP_ERROR, f"Invalid field parameter. Must be one of: {', '.join(TIMELINE_VALUE_LIST)}")
            return False

        return True

    def _greynoise_ip_reputation(self, ip, action_result):
        query_success = True

        try:
            result_data = self._api_client.ip(ip)
            result_data["visualization"] = VISUALIZATION_URL.format(ip=result_data["ip"])
        except Exception as e:
            query_success = False
            message = f"{ERROR_MESSAGE}: {self._get_error_message_from_exception(e)}"
            return action_result, query_success, message

        business_service_intelligence = result_data.get("business_service_intelligence", {}).get("found", False)
        trust_level = result_data.get("business_service_intelligence", {}).get("trust_level", "")
        internet_scanner_intelligence = result_data.get("internet_scanner_intelligence", {}).get("found", False)

        try:
            if trust_level:
                result_data["trust_level"] = TRUST_LEVELS.get(str(trust_level), trust_level)
            if not (business_service_intelligence or internet_scanner_intelligence):
                result_data["unseen_rep"] = True
            else:
                result_data["unseen_rep"] = False
        except KeyError:
            query_success = False
            return action_result, query_success, API_PARSE_ERROR_MESSAGE

        action_result.add_data(result_data)
        message = IP_REPUTATION_SUCCESS_MESSAGE
        return action_result, query_success, message

    def _greynoise_multi_ip(self, ip, action_result):
        query_success = True

        try:
            result_data = self._api_client.quick(ip)
        except Exception as e:
            query_success = False
            message = f"{ERROR_MESSAGE}: {self._get_error_message_from_exception(e)}"
            return action_result, query_success, message

        for i in result_data:
            action_result.add_data(i)

        message = LOOKUP_IPS_SUCCESS_MESSAGE

        try:
            for i in result_data:
                trust_level = i.get("business_service_intelligence", {}).get("trust_level", "")
                i["trust_level"] = TRUST_LEVELS.get(str(trust_level), trust_level)
                i["visualization"] = VISUALIZATION_URL.format(ip=i["ip"])
        except KeyError:
            query_success = False
            return action_result, query_success, API_PARSE_ERROR_MESSAGE

        return action_result, query_success, message

    def _test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            results = self._api_client.test_connection()
        except Exception as e:
            self.save_progress(f"Test Connectivity Failed with error: {self._get_error_message_from_exception(e)}")
            return action_result.set_status(phantom.APP_ERROR)

        self.save_progress(TEST_CONNECTIVITY_SUCCESS_MESSAGE)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_ip(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MESSAGE.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Extract required parameter
        ip = param["ip"]

        # check to see if it's an internal IP address
        if ipaddress.ip_address(ip).is_private:
            return action_result.set_status(phantom.APP_ERROR, INTERNAL_IP_ERROR_MESSAGE)

        action_result, query_result, message = self._greynoise_multi_ip(param["ip"], action_result)

        if not query_result:
            return action_result.set_status(phantom.APP_ERROR, message)

        return action_result.set_status(phantom.APP_SUCCESS, LOOKUP_IP_SUCCESS_MESSAGE)

    def _ip_reputation(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MESSAGE.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Extract required parameter
        ip = param["ip"]

        # check to see if it's an internal IP address
        if ipaddress.ip_address(ip).is_private:
            return action_result.set_status(phantom.APP_ERROR, INTERNAL_IP_ERROR_MESSAGE)

        action_result, query_result, message = self._greynoise_ip_reputation(ip, action_result)

        if query_result:
            return action_result.set_status(phantom.APP_SUCCESS, message)

        return action_result.set_status(phantom.APP_ERROR, message)

    def _get_cve_details(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MESSAGE.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        action_result, query_success, message = self._query_greynoise_cve(param["cve_id"], action_result)

        if query_success:
            return action_result.set_status(phantom.APP_SUCCESS, message)

        return action_result.set_status(phantom.APP_ERROR, message)

    def _query_greynoise_cve(self, cve_id, action_result):
        query_success = True

        try:
            result_data = self._api_client.cve(cve_id)
        except Exception as e:
            query_success = False
            message = f"{ERROR_MESSAGE}: {self._get_error_message_from_exception(e)}"
            return action_result, query_success, message

        action_result.add_data(result_data)
        message = GET_CVE_DETAILS_SUCCESS_MESSAGE

        return action_result, query_success, message

    def _gnql_query(self, param, is_poll=False, action_result=None):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MESSAGE.format(identifier=self.get_action_identifier()))
        if not is_poll:
            action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            exclude_raw = param.get("exclude_raw", False)
            quick = param.get("quick", False)
            query = param.get("query")

            ret_val, item_size = self._validate_integer(action_result, param.get("size", DEFAULT_SIZE_FOR_GNQL_QUERY), SIZE_ACTION_PARAM)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            message = ""
            try:
                ret_val, results, message = self._paginator(query, item_size, exclude_raw, quick)
                if phantom.is_fail(ret_val):
                    return action_result.set_status(phantom.APP_ERROR, message)
                if is_poll:
                    return results
                else:
                    if results.get("data", []):
                        for ip_info in results.get("data", []):
                            trust_level = ip_info.get("business_service_intelligence", {}).get("trust_level", "")
                            ip_info["trust_level"] = TRUST_LEVELS.get(str(trust_level), trust_level)
                            ip_info["visualization"] = VISUALIZATION_URL.format(ip=ip_info["ip"])
                    action_result.add_data(results)
            except KeyError:
                error_message = API_PARSE_ERROR_MESSAGE
                return action_result.set_status(phantom.APP_ERROR, error_message)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, urllib.parse.unquote(error_message))

        return action_result.set_status(phantom.APP_SUCCESS, GNQL_QUERY_SUCCESS_MESSAGE)

    def _paginator(self, query, size=None, exclude_raw=False, quick=False):
        """Fetch paginated results for a GreyNoise query."""
        query_response = {"data": []}
        message = "Successfully fetched query data"

        # Calculate optimal page size
        page_size = 1000
        remaining = size  # Track remaining items to fetch

        scroll = None  # Initial pagination token

        try:
            while True:
                # Calculate optimal page size for this request
                if remaining is not None:
                    page_size = min(1000, remaining)
                    if page_size <= 0:
                        break  # We've collected enough data

                # Make API call
                api_response = self._api_client.query(query=query, size=page_size, exclude_raw=exclude_raw, quick=quick, scroll=scroll)

                # Extract data and metadata
                current_data = api_response.get("data", [])
                request_metadata = api_response.get("request_metadata", {})

                # Check for empty results
                if request_metadata.get("count", 0) == 0:
                    message = "No Results Found"
                    break

                # Update custom message if available
                if request_metadata.get("message"):
                    message = request_metadata.get("message")

                # Add current data to results
                query_response["data"].extend(current_data)

                # Update remaining count
                if remaining is not None:
                    remaining -= len(current_data)
                    if remaining <= 0:
                        break

                # Get scroll token for next page
                scroll = request_metadata.get("scroll")
                if not scroll:
                    break  # No more pages available

        except Exception as e:
            message = f"Error occurred while fetching query details: {self._get_error_message_from_exception(e)}"
            return phantom.APP_ERROR, query_response, message

        return phantom.APP_SUCCESS, query_response, message

    def _lookup_ip_timeline(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MESSAGE.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        # Extract required parameter
        ip = param["ip"]
        field = param.get("field", "classification")

        # Optional parameters
        days = param.get("days", 30)  # default to 30
        granularity = param.get("granularity", "1d")  # default to 1d

        # validate the days parameter
        ret_val_days, days = self._validate_integer(action_result, days, "days", allow_zero=True)
        if phantom.is_fail(ret_val_days):
            return action_result.get_status()

        # Validate field parameter
        if not self._validate_timeline_field(field, action_result):
            return action_result

        try:
            results = self._api_client.timeline(ip, field=field, days=days, granularity=granularity)
            action_result.add_data(results)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        return action_result.set_status(phantom.APP_SUCCESS, NOISE_IP_TIMELINE_SUCCESS_MESSAGE)

    def _lookup_ips(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MESSAGE.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, ips = self._validate_comma_separated_ips(action_result, param["ips"], "ips")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        result_data, query_result, message = self._greynoise_multi_ip(ips, action_result)

        if not query_result:
            return action_result.set_status(phantom.APP_ERROR, message)

        return action_result.set_status(phantom.APP_SUCCESS, LOOKUP_IPS_SUCCESS_MESSAGE)

    def _on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        param["query"] = config.get("on_poll_query")

        if self.is_poll_now():
            self.save_progress("Starting query based on configured GNQL")
            param["size"] = param.get(phantom.APP_JSON_CONTAINER_COUNT, DEFAULT_SIZE_FOR_ON_POLL)
        else:
            on_poll_size = config.get("on_poll_size", DEFAULT_SIZE_FOR_ON_POLL)
            # Validate 'on_poll_size' config parameter
            ret_val, on_poll_size = self._validate_integer(action_result, on_poll_size, ONPOLL_SIZE_CONFIG_PARAM)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            param["size"] = on_poll_size

        if param["query"] == "Please refer to the documentation":
            self.save_progress(ON_POLL_DEFAULT_QUERY_ERROR_MESSAGE)
            return action_result.set_status(phantom.APP_ERROR, "Default on poll query unchanged")

        query_results = self._gnql_query(param, is_poll=True, action_result=action_result)
        if isinstance(query_results, bool) and phantom.is_fail(query_results):
            return action_result.get_status()

        if not query_results:
            return action_result.set_status(phantom.APP_SUCCESS, NO_DATA_FOUND_MESSAGE)

        self.save_progress("Creating containers")
        for result in query_results["data"]:
            ip = result.get("ip")
            container = {}
            container["name"] = f"GreyNoise Alert - {ip}"
            self.save_progress(f"Creating container for IP: {ip}")
            classification = result.get("internet_scanner_intelligence", {}).get("classification", "")
            container_severity = SEVERITY_MAP.get(classification)
            # if classification is empty then the severty of the container will be MEDIUM by default
            container["severity"] = container_severity
            container["description"] = f"Container was generated due to an on poll action with the query - {param['query']}"

            ret_val, message, cid = self.save_container(container)
            if phantom.is_fail(ret_val):
                self.save_progress(f"Error saving container: {message}")
                self.debug_print(f"Error saving container: {message} -- CID: {cid}")
            artifact = {"cef": result, "name": "Observed Details", "severity": container_severity, "container_id": cid}

            create_artifact_status, create_artifact_message, _ = self.save_artifact(artifact)
            if phantom.is_fail(create_artifact_status):
                self.save_progress(f"Error saving artifact: {create_artifact_message}")
                self.debug_print(f"Error saving artifact: {create_artifact_message}")
                continue

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action = self.get_action_identifier()

        if action == "test_connectivity":
            ret_val = self._test_connectivity(param)
        elif action == "lookup_ip":
            ret_val = self._lookup_ip(param)
        elif action == "ip_reputation":
            ret_val = self._ip_reputation(param)
        elif action == "gnql_query":
            ret_val = self._gnql_query(param)
        elif action == "lookup_ips":
            ret_val = self._lookup_ips(param)
        elif action == "on_poll":
            ret_val = self._on_poll(param)
        elif action == "lookup_ip_timeline":
            ret_val = self._lookup_ip_timeline(param)
        elif action == "get_cve_details":
            ret_val = self._get_cve_details(param)

        return ret_val

    def initialize(self):
        """Initialize the Phantom integration."""
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}
            return self.set_status(phantom.APP_ERROR, GREYNOISE_STATE_FILE_CORRUPT_ERROR)

        config = self.get_config()

        self._api_key = config["api_key"]
        app_json = self.get_app_json()
        self._app_version = app_json["app_version"]

        self.set_validator("ip", self._is_valid_ip)

        try:
            api_config = APIConfig(api_key=self._api_key, timeout=30, integration_name=self._integration_name)
            self._api_client = GreyNoise(api_config)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, f"{ERROR_MESSAGE}: {self._get_error_message_from_exception(e)}")

        self.save_progress("Session initialized successfully")

        return phantom.APP_SUCCESS

    def finalize(self):
        """Finalize the Phantom integration."""
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument("-v", "--verify", action="store_true", help="verify", required=False, default=False)

    args = argparser.parse_args()
    verify = args.verify
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=GREYNOISE_DEFAULT_TIMEOUT)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=GREYNOISE_DEFAULT_TIMEOUT)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(0)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = GreyNoiseConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
