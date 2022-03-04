# File: greynoise_connector.py
#
# Copyright (c) GreyNoise, 2021-2022.
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
from __future__ import print_function, unicode_literals

import ipaddress
import json
import urllib.parse
from datetime import datetime

# Phantom App imports
import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from six.moves.urllib.parse import urljoin as _urljoin

from greynoise import GreyNoise
from greynoise_consts import *


def urljoin(base, url):
    return _urljoin("%s/" % base.rstrip("/"), url.lstrip("/"))


class GreyNoiseConnector(BaseConnector):
    """Connector for GreyNoise App."""

    def __init__(self):
        """GreyNoise App Constructor."""
        super(GreyNoiseConnector, self).__init__()
        self._session = None
        self._app_version = None
        self._api_key = None
        self._integration_name = "splunk-soar-v2.2.0"

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.

        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_msg = ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except:
            pass

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return (
                        action_result.set_status(
                            phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)
                        ),
                        None,
                    )

                parameter = int(parameter)
            except Exception:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)
                    ),
                    None,
                )
            if parameter < 0:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key=key)
                    ),
                    None,
                )
            if not allow_zero and parameter == 0:
                return (action_result.set_status(phantom.APP_ERROR, NON_NEG_NON_ZERO_INT_MSG.format(key=key)), None)

        return phantom.APP_SUCCESS, parameter

    def _validate_comma_sparated_ips(self, action_result, field, key):
        """
        Validate the comma separated ips. This method operates in 4 steps:
        1. Get list with comma as the seperator
        2. Filter empty values from the list
        3. Validate the non-empty ip value
        4. Re-create the string with non-empty values.
        :param action_result: Action result object
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, filtered string or None in case of failure
        """
        if field:
            fields_list = [value.strip() for value in field.split(',') if value.strip()]
            for value in field.split(','):
                if value.strip():
                    value = value.strip()
                    if not self._is_ip(value):
                        return action_result.set_status(phantom.APP_ERROR, GREYNOISE_ERR_INVALID_IP.format(ip=value)), None
                    fields_list.append(value)

            if not fields_list:
                return action_result.set_status(phantom.APP_ERROR, GREYNOISE_ERR_INVALID_FIELDS.format(field=key)), None
            return phantom.APP_SUCCESS, ','.join(fields_list)
        return phantom.APP_SUCCESS, field

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and returns True if the address is a valid IPV6 address.
        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        # If interface is present in the IP, it will be separated by the %
        if '%' in input_ip_address:
            ip_address_input = input_ip_address.split('%')[0]

        try:
            ipaddress.ip_address(ip_address_input)
        except Exception:
            return False

        return True

    def get_session(self):
        if self._session is None:
            self._session = requests.Session()
            self._session.params.update({"api-key": self._api_key})
        return self._session

    def _make_rest_call(
        self, action_result, method, *args, **kwargs
    ):
        error_on_404 = False
        session = self.get_session()

        response_json = None
        status_code = None
        try:
            r = session.request(method, *args, **kwargs)
            if r.status_code != 404 or error_on_404:
                r.raise_for_status()
            status_code = r.status_code
        except requests.exceptions.HTTPError as e:
            err_msg = self._get_error_message_from_exception(e)
            err_msg = urllib.parse.unquote(err_msg)
            if "404" in err_msg:
                try:
                    response_json = r.json()
                    ret_val = phantom.APP_SUCCESS
                except Exception as e:
                    err_msg = self._get_error_message_from_exception(e)
                    ret_val = action_result.set_status(
                        phantom.APP_ERROR,
                        "Unable to parse JSON response. Error: {0}".format(err_msg),
                    )
            else:
                ret_val = action_result.set_status(
                    phantom.APP_ERROR,
                    "HTTP error occurred while making REST call: {0}".format(err_msg),
                )
        except requests.exceptions.ConnectionError as e:
            err_msg = self._get_error_message_from_exception(e)
            err_msg = 'Error connecting to server. Connection refused from server: {0}'.format(err_msg)
            ret_val = action_result.set_status(phantom.APP_ERROR, err_msg)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            ret_val = action_result.set_status(
                phantom.APP_ERROR,
                "General error occurred while making REST call: {0}".format(err_msg),
            )
        else:
            try:
                response_json = r.json()
                ret_val = phantom.APP_SUCCESS
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                ret_val = action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(err_msg),
                )

        return (ret_val, response_json, status_code)

    def _check_apikey(self, action_result):
        self.save_progress("Testing API key")
        ret_val, response_json, status_code = self._make_rest_call(
            action_result, "get", API_KEY_CHECK_URL, headers=self._headers)

        if phantom.is_fail(ret_val):
            self.save_progress("API key check Failed")
            return ret_val

        license_type = response_json.get("offering")
        expiration = str(response_json.get("expiration"))
        try:
            past = datetime.strptime(expiration, "%Y-%m-%d")
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(self._get_error_message_from_exception(e))
            )
        present = datetime.now()

        if response_json is None:
            self.save_progress("No response from API")
            return action_result.set_status(phantom.APP_ERROR, "No response from API")
        elif response_json.get("message") == "pong":
            if past < present:
                self.save_progress("Validated API Key. License type: {license_type}, Expiration: {expiration}".format(
                    license_type=license_type,
                    expiration=expiration))
                self.save_progress("Your licence is expired and therefore your API key has community permissions")
                self.debug_print("Validated API Key. License type: {license_type}, Expiration: {expiration}".format(
                    license_type=license_type,
                    expiration=expiration))
                self.debug_print("Your licence is expired and therefore your API key has community permissions")
                return phantom.APP_SUCCESS
            else:
                self.save_progress("Validated API Key. License type: {license_type}, Expiration: {expiration}".format(
                    license_type=license_type,
                    expiration=expiration))
                self.debug_print("Validated API Key. License type: {license_type}, Expiration: {expiration}".format(
                    license_type=license_type,
                    expiration=expiration))
                return phantom.APP_SUCCESS
        else:
            self.save_progress("Invalid response from API")
            try:
                response_json = json.dumps(response_json)
            except Exception:
                return action_result.set_status(
                    phantom.APP_ERROR, "Invalid response from API"
                )
            return action_result.set_status(
                phantom.APP_ERROR, "Invalid response from API: %s" % response_json
            )

    # check the config for the type of license to determine which actions can be used
    def _check_license_type(self):
        config = self.get_config()

        license_type = "enterprise"
        message = "Enterprise license."

        if(config.get("license_type") == "community"):
            license_type = "community"
            message = "This action cannot be used with the community API. Please check the settings in the GreyNoise app config."

        return license_type, message

    def _greynoise_quick_ip(self, ip, action_result, session):

        query_success = True

        try:
            result_data = session.quick(ip)
            result_data = result_data[0]
        except Exception:
            query_success = False
            return action_result, query_success, ERROR_MESSAGE

        # format data for quick lookup for visualizer

        action_result.add_data(result_data)
        message = "IP Lookup action successfully completed"

        try:
            result_data["visualization"] = VISUALIZATION_URL.format(
                ip=result_data["ip"]
            )
        except KeyError:
            query_success = False
            return action_result, query_success, API_PARSE_ERROR_MESSAGE

        return action_result, query_success, message

    def _greynoise_riot_ip(self, ip, action_result, session):

        query_success = True

        try:
            result_data = session.riot(ip)
        except Exception:
            query_success = False
            return action_result, query_success, ERROR_MESSAGE

        action_result.add_data(result_data)
        message = "RIOT Lookup IP action successfully completed"

        try:
            result_data["visualization"] = VISUALIZATION_URL.format(
                ip=result_data["ip"]
            )
            if result_data["riot"] is False:
                result_data["riot_unseen"] = True
            if "trust_level" in result_data.keys():
                if str(result_data["trust_level"]) in TRUST_LEVELS:
                    result_data["trust_level"] = TRUST_LEVELS[str(result_data["trust_level"])]
        except KeyError:
            query_success = False
            return action_result, query_success, API_PARSE_ERROR_MESSAGE

        return action_result, query_success, message

    def _greynoise_noise_ip(self, ip, action_result, session):

        query_success = True

        try:
            result_data = session.ip(ip)
        except Exception:
            query_success = False
            return action_result, query_success, ERROR_MESSAGE

        action_result.add_data(result_data)
        message = "IP reputation action successfully completed"

        try:
            result_data["visualization"] = VISUALIZATION_URL.format(
                ip=result_data["ip"]
            )
            if result_data["seen"] is False:
                result_data["unseen_rep"] = True
        except KeyError:
            query_success = False
            return action_result, query_success, API_PARSE_ERROR_MESSAGE

        return action_result, query_success, message

    def _greynoise_multi_ip(self, ip, action_result, session):
        # remove any spaces before querying
        ip = ip.replace(" ", "")

        query_success = True

        try:
            result_data = session.quick(ip)
        except Exception:
            query_success = False
            return action_result, query_success, ERROR_MESSAGE

        action_result.add_data(result_data)
        message = "Lookup IPs action successfully completed"

        try:
            for i in result_data:
                i["visualization"] = VISUALIZATION_URL.format(
                    ip=i["ip"]
                )
        except KeyError:
            query_success = False
            return action_result, query_success, API_PARSE_ERROR_MESSAGE

        return action_result, query_success, message

    def _greynoise_community_ip(self, ip, action_result, session):

        query_success = True

        try:
            result_data = session.ip(ip)
        except Exception:
            query_success = False
            return action_result, query_success, ERROR_MESSAGE

        action_result.add_data(result_data)
        message = "Lookup IPs action successfully completed"

        try:
            result_data["visualization"] = VISUALIZATION_URL.format(
                ip=result_data["ip"]
            )
            if result_data["riot"] is False and result_data['noise'] is False:
                result_data["community_not_found"] = True
        except KeyError:
            query_success = False
            return action_result, query_success, API_PARSE_ERROR_MESSAGE

        return action_result, query_success, message

    def _query_greynoise_ip(self, ip, query_type, action_result):

        session = GreyNoise(api_key=self._api_key, integration_name=self._integration_name)
        self.debug_print("Session initialized successfully")

        # check to see if it's an internal IP address
        if(query_type != "multi" and ipaddress.ip_address(ip).is_private):
            query_success = False
            message = "Internal IP"
            return action_result, query_success, INTERNAL_IP_ERROR_MESSAGE

        # if it's not an internal IP format the query for the type of data
        if query_type == "quick":
            action_result, query_success, message = self._greynoise_quick_ip(ip, action_result, session)

        elif query_type == "riot":
            action_result, query_success, message = self._greynoise_riot_ip(ip, action_result, session)

        elif query_type == "noise":
            action_result, query_success, message = self._greynoise_noise_ip(ip, action_result, session)

        elif query_type == "multi":
            action_result, query_success, message = self._greynoise_multi_ip(ip, action_result, session)

        elif query_type == "community":
            session = GreyNoise(api_key=self._api_key, integration_name=self._integration_name, offering="community")
            self.debug_print("Session initialized successfully")
            action_result, query_success, message = self._greynoise_community_ip(ip, action_result, session)

        return action_result, query_success, message

    def _test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return ret_val

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_ip(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        license_type, message = self._check_license_type()
        if(license_type == "community"):
            return action_result.set_status(phantom.APP_ERROR, message)

        action_result, query_result, message = self._query_greynoise_ip(param["ip"], "quick", action_result)

        if(query_result):
            return action_result.set_status(phantom.APP_SUCCESS, message)

        return action_result.set_status(phantom.APP_ERROR, message)

    def _riot_lookup_ip(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        license_type, message = self._check_license_type()
        if(license_type == "community"):
            return action_result.set_status(phantom.APP_ERROR, message)

        action_result, query_result, message = self._query_greynoise_ip(param["ip"], "riot", action_result)

        if(query_result):
            return action_result.set_status(phantom.APP_SUCCESS, message)

        return action_result.set_status(phantom.APP_ERROR, message)

    def _community_lookup_ip(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        action_result, query_result, message = self._query_greynoise_ip(param["ip"], "community", action_result)

        if(query_result):
            return action_result.set_status(phantom.APP_SUCCESS, message)

        return action_result.set_status(phantom.APP_ERROR, message)

    def _ip_reputation(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        license_type, message = self._check_license_type()
        if(license_type == "community"):
            return action_result.set_status(phantom.APP_ERROR, message)

        action_result, query_result, message = self._query_greynoise_ip(param["ip"], "noise", action_result)

        if(query_result):
            return action_result.set_status(phantom.APP_SUCCESS, message)

        return action_result.set_status(phantom.APP_ERROR, message)

    def _gnql_query(self, param, is_poll=False, action_result=None):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        if not is_poll:
            action_result = self.add_action_result(ActionResult(dict(param)))

        license_type, message = self._check_license_type()
        if(license_type == "community"):
            return action_result.set_status(phantom.APP_ERROR, message)

        session = GreyNoise(api_key=self._api_key, integration_name=self._integration_name)
        query_results = []
        try:

            # make the initial query and add it to the query_results dict
            results = session.query(param["query"])

            if is_poll:
                query_results.append(results["data"])

                # if necessary add the additional results to the query_results dict
                while("scroll" in results):
                    results = session.query(param["query"], scroll=param["query"])
                    query_results.append(results["data"])

                self.save_progress("GreyNoise query complete")

                return query_results
            else:
                query_results.append(results)

                # if necessary add the additional results to the query_results dict
                while("scroll" in results):
                    results = session.query(param["query"], scroll=param["query"])
                    query_results.append(results["data"])

                # this gets parsed a little differently from poll now in order to fit in with the view
                full_response = query_results[0]

                # check the number of results to return
                ret_val, item_size = self._validate_integer(
                    action_result, param["size"], SIZE_ACTION_PARAM
                )
                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                if(full_response["count"] <= item_size):
                    action_result.add_data(full_response)

                # if there are more results than what is requested delete them from the query results
                if(full_response["count"] > item_size):
                    temp = []
                    for i in range(item_size):
                        temp.append(full_response["data"][i])
                    del full_response["data"]
                    del full_response["count"]
                    full_response["data"] = temp
                    full_response["count"] = len(temp)
                    action_result.add_data(full_response)

                try:
                    for entry in full_response["data"]:
                        entry["visualization"] = VISUALIZATION_URL.format(ip=entry["ip"])
                except KeyError:
                    error_msg = "Error occurred while processing API response"
                    return action_result.set_status(phantom.APP_ERROR, error_msg)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err_msg)

        return action_result.set_status(phantom.APP_SUCCESS, "GNQL Query action successfully completed")

    def _lookup_ips(self, param):
        self.save_progress(GREYNOISE_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        license_type, message = self._check_license_type()
        if(license_type == "community"):
            return action_result.set_status(phantom.APP_ERROR, message)

        ret_val, ips = self._validate_comma_sparated_ips(action_result, param['ips'], 'ips')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        result_data, query_result, message = self._query_greynoise_ip(ips, "multi", action_result)

        if(query_result):
            return action_result.set_status(phantom.APP_SUCCESS, message)

        return action_result.set_status(phantom.APP_ERROR, message)

    def _on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if self.is_poll_now():
            self.save_progress(
                "Starting query based on configured GNQL"
            )

        config = self.get_config()
        param["query"] = config.get("on_poll_query")

        if self.is_poll_now():
            param["size"] = param.get(phantom.APP_JSON_CONTAINER_COUNT, 25)
        else:
            on_poll_size = config.get("on_poll_size", 25)
            # Validate 'on_poll_size' config parameter
            ret_val, on_poll_size = self._validate_integer(
                action_result, on_poll_size, ONPOLL_SIZE_CONFIG_PARAM
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            param["size"] = on_poll_size

        if param["query"] == "Please refer to the documentation":
            self.save_progress(
                "Default on poll query unchanged, please enter a valid GNQL query"
            )
            return action_result.set_status(
                phantom.APP_ERROR, "Default on poll query unchanged"
            )

        query_results = self._gnql_query(param, is_poll=True, action_result=action_result)
        if isinstance(query_results, bool) and phantom.is_fail(query_results):
            return action_result.get_status()

        if not query_results:
            return action_result.set_status(phantom.APP_SUCCESS, "No Data Found")

        self.save_progress("Creating containers")
        for i in query_results[0][-int(param["size"]):]:
            container = {}
            container["name"] = "GreyNoise Alert - {}".format(i["ip"])
            # set the severity of the container based on the classification
            container_severity = "low"
            if i["classification"] == "malicious":
                container_severity = "high"
            elif i["classification"] == "unknown":
                container_severity == "medium"

            container["severity"] = container_severity
            container["description"] = "This container was generated due to an on poll action with the query - {}".format(param["query"])

            ret_val, msg, cid = self.save_container(container)
            if phantom.is_fail(ret_val):
                self.save_progress("Error saving container: {}".format(msg))
                self.debug_print("Error saving container: {} -- CID: {}".format(msg, cid))

            artifact = [{
                'cef': i,
                'name': 'Observed Details',
                'severity': container_severity,
                'container_id': cid
            }]

            create_artifact_status, create_artifact_msg, _ = self.save_artifacts(artifact)
            if phantom.is_fail(create_artifact_status):
                self.save_progress("Error saving artifact: {}".format(create_artifact_msg))
                self.debug_print("Error saving artifact: {}".format(create_artifact_msg))
                continue

        # iterate through query_results and create a container for each IP returned from GN

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
        elif action == "riot_lookup_ip":
            ret_val = self._riot_lookup_ip(param)
        elif action == "community_lookup_ip":
            ret_val = self._community_lookup_ip(param)

        return ret_val

    def initialize(self):
        """Initialize the Phantom integration."""
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}
            return self.set_status(phantom.APP_ERROR, GREYNOISE_STATE_FILE_CORRUPT_ERR)

        config = self.get_config()

        self._api_key = config["api_key"]
        app_json = self.get_app_json()
        self._app_version = app_json["app_version"]

        self.set_validator('ip', self._is_ip)

        self._headers = {
            "Accept": "application/json",
            "key": self._api_key,
            "User-Agent": "greynoise-phantom-integration-v{0}".format(
                self._app_version
            ),
        }

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

    args = argparser.parse_args()
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
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

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

    exit(0)
