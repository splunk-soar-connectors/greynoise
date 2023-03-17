# File: greynoise_view.py
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
# and limitations under the License.

import logging

logger = logging.getLogger(__name__)


def _parse_data(data, param):  # noqa: C901

    try:
        res = {}

        # parsing data for lookup ip action
        if 'ip' in param.keys() and "code" in data[0].keys():
            for item in data:
                res['ip'] = item['ip']
                res['noise'] = item['noise']
                res['code_message'] = item['code_message']
                res['visualization'] = item['visualization']
        # parsing data for community action
        elif 'ip' in param.keys() and (
                ("riot" in data[0].keys() and "noise" in data[0].keys()) or "plan" in data[0].keys()):
            if "plan" in data[0].keys():
                for item in data:
                    res['plan'] = item['plan']
                    res['ratelimit'] = item['rate-limit']
                    res['plan_url'] = item['plan_url']
                    res['message'] = item['message']
            elif "name" in data[0].keys():
                for item in data:
                    res['ip'] = item['ip']
                    res['noise'] = item['noise']
                    res['riot'] = item['riot']
                    res['classification'] = item['classification']
                    res['name'] = item['name']
                    res['link'] = item['link']
                    res['last_seen'] = item['last_seen']
                    res['message'] = item['message']
            else:
                for item in data:
                    res['ip'] = item['ip']
                    res['noise'] = item['noise']
                    res['riot'] = item['riot']
                    res['message'] = item['message']
                    res['community_not_found'] = item['community_not_found']
        # parsing data for riot action
        elif 'ip' in param.keys() and (
                ("riot" in data[0].keys() and "category" in data[0].keys()) or "riot_unseen" in data[0].keys()):
            if "riot_unseen" in data[0].keys():
                for item in data:
                    res['ip'] = item['ip']
                    res['riot'] = item['riot']
                    res['riot_unseen'] = item['riot_unseen']
            else:
                for item in data:
                    res['ip'] = item['ip']
                    res['riot'] = item['riot']
                    res['category'] = item['category']
                    res['name'] = item['name']
                    res['description'] = item['description']
                    res['explanation'] = item['explanation']
                    res['last_updated'] = item['last_updated']
                    res['trust_level'] = item['trust_level']
                    res['reference'] = item['reference']
                    res['visualization'] = item['visualization']
        # parsing data for lookup ips action
        elif 'ips' in param.keys():
            ip_return_list = []
            temp_dict = {}
            for item in data[0]:
                temp_dict['ip'] = item['ip']
                temp_dict['noise'] = item['noise']
                temp_dict['code_message'] = item['code_message']
                temp_dict['visualization'] = item['visualization']
                ip_return_list.append(temp_dict.copy())
            res['lookup_ips'] = ip_return_list
        # parsing data for ip reputation action
        elif 'ip' in param.keys() and 'seen' in data[0].keys() and 'query' not in param.keys():
            if data[0]['seen'] is False:
                res['ip'] = data[0]["ip"]
                res['seen'] = data[0]['seen']
                res['unseen_rep'] = data[0]['unseen_rep']
                res['first_seen'] = "This IP has never been seen scanning the internet"
                res['last_seen'] = "This IP has never been seen scanning the internet"
            else:
                res['ip'] = data[0]['ip']
                res['seen'] = data[0]['seen']
                res['classification'] = data[0]['classification']
                res['first_seen'] = data[0]['first_seen']
                res['last_seen'] = data[0]['last_seen']
                res['visualization'] = data[0]['visualization']
                res['actor'] = data[0]['actor']
                res['organization'] = data[0]['metadata']['organization']
                res['asn'] = data[0]['metadata']['asn']
                if data[0]['metadata']['country']:
                    res['country'] = data[0]['metadata']['country']
                if data[0]['metadata']['destination_countries']:
                    res['destination_countries'] = ', '.join(data[0]['metadata']['destination_countries'])
                if data[0]['metadata']['city']:
                    res['city'] = data[0]['metadata']['city']
                res['tags'] = data[0]['tags']
                res['viz_tags'] = ", ".join(data[0]['tags'])
                res['cve'] = ", ".join(data[0]['cve'])
        # parse ip timeline data
        elif 'ip' in param.keys() and 'activity' in data[0].keys():
            if "message" in data[0] and "Not allowed" in data[0]["message"]:
                res['ip'] = param["ip"]
                res['message'] = data[0]["message"]
            elif not data[0]["activity"]:
                res['ip'] = param["ip"]
                res['message'] = "No Timeline Data Available"
            else:
                for item in data[0]["activity"]:
                    item["timestamp"] = item["timestamp"].split("T")[0]
                    item["http_user_agents"] = ', '.join(item["http_user_agents"])
                    item["http_paths"] = ', '.join(item["http_paths"])
                    tags = []
                    for tag in item["tags"]:
                        tags.append(tag["name"])
                    item["tags"] = ', '.join(tags)
                    ports = []
                    for protocol in item["protocols"]:
                        ports.append(str(protocol["port"]) + "/" + str(protocol["transport_protocol"]))
                    item["protocols"] = ', '.join(ports)
                res['ip'] = data[0]["metadata"]["ip"]
                res['start_time'] = data[0]["metadata"]["start_time"]
                res['end_time'] = data[0]["metadata"]["end_time"]
                res["activity"] = data[0]["activity"]
                res["message"] = f"Show {param['days']} days of daily scanning activity for {param['ip']}"
                res["link"] = f"https://viz.greynoise.io/ip/{param['ip']}?view=timeline"
        # parse ip sim data
        elif 'ip' in param.keys() and 'similar_ips' in data[0].keys():
            if "message" in data[0]:
                res['ip'] = param["ip"]
                res['message'] = data[0]["message"]
            elif data[0]["total"] == 0:
                res['ip'] = param["ip"]
                res['message'] = "No Similar IPs Found"
            else:
                for item in data[0]["similar_ips"]:
                    item["features"] = ', '.join(item["features"])
                    item["score"] = str(int(item["score"] * 100)) + "%"
                res['ip'] = data[0]["ip"]["ip"]
                res["similar_ips"] = data[0]["similar_ips"]
                res["link"] = f"https://viz.greynoise.io/ip-similarity/{param['ip']}"
                if data[0]["total"] > param['limit']:
                    res[
                        "message"] = f"Showing first {param['limit']} IPs of {data[0]['total']} IPs that have a " \
                                     f"similarity score of {param['min_score']}% or above to {param['ip']} "
                else:
                    res[
                        "message"] = f"Showing {data[0]['total']} IPs that have a " \
                                     f"similarity score of {param['min_score']}% or above to {param['ip']} "
        # parsing data for gnql query
        elif 'query' in param.keys():
            gnql_list = []
            temp_dict = {}
            if data[0]["count"] == 0:
                res['query'] = data[0]['query']
                res['message'] = data[0]['message']
            else:
                for item in data[0]["data"]:
                    temp_dict['ip'] = item['ip']
                    temp_dict['classification'] = item['classification']
                    temp_dict['first_seen'] = item['first_seen']
                    temp_dict['last_seen'] = item['last_seen']
                    temp_dict['visualization'] = item['visualization']
                    temp_dict['actor'] = item['actor']
                    temp_dict['organization'] = item['metadata']['organization']
                    temp_dict['asn'] = item['metadata']['asn']
                    if item['metadata']['country']:
                        temp_dict['country'] = item['metadata']['country']
                    if item['metadata']['destination_countries']:
                        temp_dict['destination_countries'] = ', '.join(item['metadata']['destination_countries'])
                    if item['metadata']['city']:
                        temp_dict['city'] = item['metadata']['city']
                    temp_dict['tags'] = item['tags']
                    temp_dict['viz_tags'] = ", ".join(item['tags'])
                    temp_dict['cve'] = ", ".join(item['cve'])
                    gnql_list.append(temp_dict.copy())
                res['gnql_query'] = gnql_list
                res['message'] = "results"
        return res

    except Exception as err:
        logger.warning('Error in _parse_data: %s' % str(err))


def _get_ctx_result(result, provides):
    try:
        ctx_result = {}

        param = result.get_param()
        summary = result.get_summary()
        data = result.get_data()

        ctx_result['param'] = param
        if summary:
            ctx_result['summary'] = summary

        if not data:
            ctx_result['data'] = {}
            return ctx_result

        parsed_data = _parse_data(data, ctx_result['param'])

        ctx_result['data'] = parsed_data
        return ctx_result
    except Exception as err:
        logger.warning('Error in _get_ctx_result: %s' % str(err))


def report(provides, all_app_runs, context):
    try:
        context["results"] = []
        for summary, action_results in all_app_runs:
            for result in action_results:
                ctx_result = _get_ctx_result(result, provides)
                if ctx_result:
                    context["results"].append(ctx_result)

        return "greynoise_view_reports.html"
    except Exception as err:
        logger.warning('Error in report: %s' % str(err))
