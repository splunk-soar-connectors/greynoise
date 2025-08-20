# GreyNoise for SOAR

Publisher: GreyNoise \
Connector Version: 2.3.3 \
Product Vendor: GreyNoise \
Product Name: GreyNoise \
Minimum Product Version: 6.4.1

This app provides investigative capabilities using the GreyNoise plugin and supports receiving alerts and feeds via webhook from GreyNoise

This release incorporates API v3, designed to be easier to use and more powerful.
It introduces support for new fields and capabilities to help you get more value from the GreyNoise platform. [Here’s a quick overview.](https://docs.greynoise.io/docs/api-v3-whats-new-vs-v2#/)

As part of this update, we streamlined the offering by removing certain endpoints and deprecated some actions from our Splunk SOAR integration.
The following actions are no longer supported in the GreyNoise for Splunk SOAR integration:

- community lookup ip (use ip reputation action instead)
- riot lookup ip (use ip reputation action instead)
- similar noise ips

If you have any questions about this transition, please don’t hesitate to reach out.
You can find our updated API documentation linked [here](https://docs.greynoise.io/reference).

## ⚠️ Playbook Backward Compatibility

- GreyNoise SDK version is upgraded to v3.0.1 in connector version 3.0.0.
- With this version, there are changes in:
  1. Data paths for various actions.
  1. CEF fields ingested via on-poll action.
  1. Certain actions have been removed (see above list); update playbooks to use the recommended replacement actions where applicable.

## Configure Webhook in Connector

- Connector version 3.0.0 supports receiving data via webhook from GreyNoise. The detailed steps to configure webhooks in connector are available below:

### Configure Administration Settings

1. Enable webhook services in Splunk SOAR by following the official guide: [Manage webhooks in Splunk SOAR](https://help.splunk.com/en/splunk-soar/soar-on-premises/administer-soar-on-premises/6.4.1/configure-administration-settings-in-splunk-soar-on-premises/manage-webhooks-in-splunk-soar-on-premises)
1. Adjust the rate limit of the webhooks service based on the expected data volume from GreyNoise. Setting the limit too low may result in data loss.

### Configure Webhook in Connector

1. The webhook can be enabled from the Webhook Settings tab in Asset Configuration page of connector.
1. On the Webhook Settings tab, enable the "Enable webhooks for this asset" checkbox to enable the webhook for this asset. Modifying any other settings in this tab may cause issues in data ingestion.
1. After saving the Asset Configuration page, the webhook URL will be displayed in the Webhook Settings tab under "URL for this webhook" field.
1. Copy the webhook URL to add it to GreyNoise.

> **Note:** The webhook URL allows unauthenticated data submission to Splunk SOAR. Handle it as sensitive information.

### Test Webhook (Optional)

1. Before setting up the webhook in GreyNoise, the URL can be tested using Postman, curl, or similar tools.
1. Test the webhook URL by sending a POST request to it.
1. The request body should be in JSON format and must include the following details:
   - To Test Alert ingestion via webhook, send a POST request to the webhook URL with the following JSON body:
     ```json
     {
         "timestamp": "2023-10-05T14:55:00Z",
         "alert": {
             "id": "alert-id",
             "name": "Test Alert",
             "type": "query",
             "creator": "creator-email"
         },
         "data": [
             {
                 "ip": "10.0.0.1",
                 "classification": "malicious"
             },
             {
                 "ip": "10.0.0.2",
                 "classification": "suspicious"
             },
             {
                 "ip": "10.0.0.3",
                 "classification": "benign"
             },
             {
                 "ip": "10.0.0.4",
                 "classification": "unknown"
             }
         ],
         "viz_link": "https://viz.example.com/query/12345",
         "query_link": "https://api.example.com/v2/experimental/gnql?query=12345",
         "alert_link": "https://viz.example.com/account/alerts?alert=12345"
     }
     ```
   - To test IP Feed ingestion via webhook, send a POST request to the webhook URL with the following JSON body:
     ```json
     {
         "event_type": "ip-classification-change",
         "ip": "8.8.8.8",
         "new_state": "benign",
         "old_state": "unknown",
         "timestamp": "2025-08-05T10:42:38Z",
         "workspace_id": "e4a5be2e-1be0-4105-a5e2-51e6a5525fa0"
     }
     ```
   - To test CVE Feed ingestion via webhook, send a POST request to the webhook URL with the following JSON body:
     ```json
     {
         "cve": "CVE-2022-31717",
         "event_type": "cve-status-change",
         "metadata": {},
         "new_state": {
             "activity_seen": true,
             "benign_ip_count_10d": 0,
             "benign_ip_count_1d": 0,
             "benign_ip_count_30d": 0,
             "threat_ip_count_10d": 1,
             "threat_ip_count_1d": 1,
             "threat_ip_count_30d": 1
         },
         "old_state": {
             "activity_seen": false,
             "benign_ip_count_10d": 0,
             "benign_ip_count_1d": 0,
             "benign_ip_count_30d": 0,
             "threat_ip_count_10d": 0,
             "threat_ip_count_1d": 0,
             "threat_ip_count_30d": 0
         },
         "timestamp": "2025-08-05T10:30:16.972504375Z"
     }
     ```
1. Check the Splunk SOAR instance to verify that the data is ingested successfully and a 200 OK response with a `status: success` message is received from the webhook.

### Configure Webhook in GreyNoise

To configure a webhook in GreyNoise:

- For Alerts: On the Alerts configuration page, check the Webhook checkbox, enter the webhook URL in the textbox, and save the settings.
- For Feeds: On the Feed configuration page, under the Webhook Delivery section, enter the webhook URL in the textbox and save the settings.

## Details of Ingested Data

### Alerts Ingestion

- For every alert triggered by GreyNoise, a new container/event will be created in Splunk SOAR instance.
- Container/event name will be in the format: "GreyNoise Alert: {Alert Name}: {Alert Type}: {Alert Timestamp} UTC"
- Connector will also add tag `greynoise-alert` to the container/event, which can be used to filter the alerts in Playbooks.
- For all the details about IP address, separate artifact will be created.
- Artifact will also have tag `greynoise-alert`, which can be used to filter the IP addresses in Playbooks.
- Note: Currently only 10 recent IP addresses will be ingested for an alert due to a limitation from GreyNoise.

### Feeds Ingestion

- For feeds, a single container/event will be created in Splunk SOAR instance for a particular day.
- Container/event name will be in the format: "GreyNoise Feed: {Current Date} UTC"
- Connector will also add tag `greynoise-feed` to the container/event, which can be used to filter the feeds in Playbooks.
- For all the details about IP Classification Change and CVE Status Change, separate artifacts will be created.
- Artifact will have tag `greynoise-feed-ip` for artifacts created via IP Classification Change and `greynoise-feed-cve` for artifacts created via CVE Status Change.

## Playbooks

The playbooks listed below can be used to automate tasks in Splunk SOAR:

- Automatically identify and contain IPs associated with known CVEs
- Enrich artifacts with reputation data to reduce noise and prioritize threats
- Automatically block or unblock IP addresses based on the GreyNoise IP Feed

These playbooks are available in the [GreyNoise Splunk SOAR Playbooks](https://github.com/GreyNoise-Intelligence/greynoise-splunk-soar-playbooks) repository.

### Configuration variables

This table lists the configuration variables required to operate GreyNoise for SOAR. These variables are specified when configuring a GreyNoise asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** | required | password | API Key for GreyNoise |
**on_poll_query** | optional | string | GNQL query to use for the on poll action |
**on_poll_size** | optional | numeric | The number of results to return for the interval/schedule poll |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration \
[lookup ip](#action-lookup-ip) - Lookup IP using GreyNoise API Quick Check Endpoint \
[ip reputation](#action-ip-reputation) - Get full GreyNoise reputation and context for a specific IP \
[gnql query](#action-gnql-query) - Use the GreyNoise Query Language to run a query \
[lookup ips](#action-lookup-ips) - Lookup IPs using GreyNoise API Multi Quick Check Endpoint (comma-separated, limit 500 per request) \
[on poll](#action-on-poll) - Get details on a specific GNQL query \
[noise ip timeline](#action-noise-ip-timeline) - GreyNoise IP Timeline lookup for events matching a specific field \
[get cve details](#action-get-cve-details) - Retrieve details about a specific Common Vulnerabilities and Exposures (CVE)

## action: 'test connectivity'

Validate the asset configuration for connectivity using the supplied configuration

Type: **test** \
Read only: **True**

Tests the connection to the paid GreyNoise API.

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'lookup ip'

Lookup IP using GreyNoise API Quick Check Endpoint

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to query | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string | `ip` | 8.8.8.8 |
action_result.data.\*.ip | string | `ip` | 8.8.8.8 |
action_result.data.\*.trust_level | string | | 1 - Reasonably Ignore |
action_result.data.\*.visualization | string | `url` | https://viz.greynoise.io/ip/1.1.1.1 |
action_result.data.\*.business_service_intelligence.found | boolean | | False True |
action_result.data.\*.business_service_intelligence.trust_level | string | | trusted |
action_result.data.\*.internet_scanner_intelligence.found | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.classification | string | | malicious benign |
action_result.status | string | | success failed |
action_result.message | string | | Lookup IP action successfully completed |
action_result.summary | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'ip reputation'

Get full GreyNoise reputation and context for a specific IP

Type: **investigate** \
Read only: **True**

Get more information about a given IP address. Returns time ranges, IP metadata (network owner, ASN, reverse DNS pointer, country), associated actors, activity tags, raw port scan, and web request information.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to query | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string | `ip` | 8.8.8.8 |
action_result.data.\*.ip | string | | 8.8.8.8 |
action_result.data.\*.unseen_rep | boolean | | True |
action_result.data.\*.trust_level | string | | 1 - Reasonably Ignore |
action_result.data.\*.visualization | string | | https://viz.greynoise.io/ip/1.1.1.1 |
action_result.data.\*.business_service_intelligence.name | string | | Google Public DNS |
action_result.data.\*.business_service_intelligence.found | boolean | | True False |
action_result.data.\*.business_service_intelligence.category | string | | public_dns |
action_result.data.\*.business_service_intelligence.reference | string | | https://developers.test.com/speed/test/test/isp#alternative |
action_result.data.\*.business_service_intelligence.description | string | | Google's global domain name system (DNS) resolution service. |
action_result.data.\*.business_service_intelligence.explanation | string | | Public DNS services are used as alternatives to ISP's name servers. You may see devices on your network communicating with Google Public DNS over port 53/TCP or 53/UDP to resolve DNS lookups. |
action_result.data.\*.business_service_intelligence.trust_level | string | | 1 |
action_result.data.\*.business_service_intelligence.last_updated | string | | 2025-08-06T13:10:58Z |
action_result.data.\*.internet_scanner_intelligence.bot | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.tor | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.vpn | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.actor | string | | |
action_result.data.\*.internet_scanner_intelligence.found | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.metadata.os | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.asn | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.rdns | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.domain | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.mobile | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.metadata.region | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.carrier | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.category | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.latitude | numeric | | |
action_result.data.\*.internet_scanner_intelligence.metadata.longitude | numeric | | |
action_result.data.\*.internet_scanner_intelligence.metadata.datacenter | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.rdns_parent | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.sensor_hits | numeric | | |
action_result.data.\*.internet_scanner_intelligence.metadata.source_city | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.organization | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.sensor_count | numeric | | |
action_result.data.\*.internet_scanner_intelligence.metadata.rdns_validated | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.metadata.source_country | string | | |
action_result.data.\*.internet_scanner_intelligence.metadata.single_destination | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.metadata.source_country_code | string | | |
action_result.data.\*.internet_scanner_intelligence.raw_data.source.bytes | numeric | | |
action_result.data.\*.internet_scanner_intelligence.last_seen | string | | |
action_result.data.\*.internet_scanner_intelligence.spoofable | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.first_seen | string | | |
action_result.data.\*.internet_scanner_intelligence.vpn_service | string | | |
action_result.data.\*.internet_scanner_intelligence.classification | string | | |
action_result.data.\*.internet_scanner_intelligence.last_seen_timestamp | string | | |
action_result.data.\*.internet_scanner_intelligence.tags.\*.id | string | | fddc4698-fb29-4fd6-946f-5598100fe716 |
action_result.data.\*.internet_scanner_intelligence.tags.\*.name | string | | MSSQL Login Attempt |
action_result.data.\*.internet_scanner_intelligence.tags.\*.slug | string | | mssql-login-attempt |
action_result.data.\*.internet_scanner_intelligence.tags.\*.created | string | | 2024-10-28 |
action_result.data.\*.internet_scanner_intelligence.tags.\*.category | string | | activity |
action_result.data.\*.internet_scanner_intelligence.tags.\*.intention | string | | suspicious |
action_result.data.\*.internet_scanner_intelligence.tags.\*.updated_at | string | | 2025-08-06T19:35:46.749018Z |
action_result.data.\*.internet_scanner_intelligence.tags.\*.description | string | | IP addresses with this tag have been observed attempting to perform a Microsoft SQL (MSSQL) login. |
action_result.data.\*.internet_scanner_intelligence.tags.\*.recommend_block | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.raw_data.scan.\*.port | numeric | | 10083 |
action_result.data.\*.internet_scanner_intelligence.raw_data.scan.\*.protocol | string | | tcp |
action_result.data.\*.internet_scanner_intelligence.raw_data.ja3.\*.port | numeric | | 9042 |
action_result.data.\*.internet_scanner_intelligence.raw_data.ja3.\*.fingerprint | string | | 19e29534fd49dd27d09234e639c4057e |
action_result.data.\*.actor | string | | Shodan.io |
action_result.data.\*.bot | boolean | | True False |
action_result.data.\*.classification | string | | benign malicious |
action_result.data.\*.cve.\* | string | | CVE-2021-12345 CVE-2023-5678 |
action_result.data.\*.first_seen | string | | 2020-12-25 |
action_result.data.\*.last_seen | string | | 2020-12-25 |
action_result.data.\*.metadata.\* | string | | { "country":"United States" "country_code":"US" "city":"Seattle" "organization":"Org. Name" "rdns":"crawl-66-249-79-17.testbot.com" "asn":"AS521" "tor":false "category":"education" "os":"Windows 7/8" } |
action_result.data.\*.metadata.asn | string | | AS12345 |
action_result.data.\*.metadata.category | string | | isp |
action_result.data.\*.metadata.city | string | | Madrid |
action_result.data.\*.metadata.destination_countries.\* | string | | Spain United Kingdom Turkey |
action_result.data.\*.metadata.destination_country_codes.\* | string | | ES GB TR |
action_result.data.\*.metadata.organization | string | | Acme, Inc |
action_result.data.\*.metadata.os | string | | Linux 3 |
action_result.data.\*.metadata.rdns | string | | bot.acme.lcl |
action_result.data.\*.metadata.region | string | | Madrid |
action_result.data.\*.metadata.source_country | string | | Spain |
action_result.data.\*.metadata.source_country_code | string | | ES |
action_result.data.\*.metadata.tor | boolean | | True False |
action_result.data.\*.raw_data.\* | string | | { "scan":[ 0:{ "port":80 "protocol":"TCP" } ] "web":{ "paths":[ 0:"/robots.txt" ] "useragents":[ 0:"test/5.0 (compatible; testbot/2.1; +http://www.test.com/bot.html)" ] } "ja3":[ 0:{ "fingerprint":"c3a6cf0bf2e690ac8e1ecf6081f17a50" "port":443 } ] } |
action_result.data.\*.raw_data.hassh.\* | string | | [{ "fingerprint":"c3a6cf0bf2e690ac8e1ecf6081f17a50" "port":443 }] |
action_result.data.\*.raw_data.ja3.\* | string | | [{ "fingerprint":"c3a6cf0bf2e690ac8e1ecf6081f17a50" "port":443 }] |
action_result.data.\*.raw_data.scan.\* | string | | [ { "port":23, "protocol":"TCP" }, { "port":80, "protocol":"TCP" }, { "port":8080, "protocol":"TCP" } ] |
action_result.data.\*.raw_data.web.\* | string | | { "paths":[ "/" ], "useragents":[ "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/8.8.8.8 Safari/537.36" ] } |
action_result.data.\*.seen | boolean | | True False |
action_result.data.\*.spoofable | boolean | | True False |
action_result.data.\*.tags.\* | string | | Mirai Telnet Worm |
action_result.data.\*.vpn | boolean | | True False |
action_result.data.\*.vpn_service | string | | PRETTY_VPN |
action_result.status | string | | success failed |
action_result.message | string | | IP Reputation action successfully completed |
action_result.summary | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'gnql query'

Use the GreyNoise Query Language to run a query

Type: **investigate** \
Read only: **True**

Please refer to <a target="_blank" rel="noopener noreferrer" href="https://docs.greynoise.io/docs/using-the-greynoise-query-language-gnql">https://docs.greynoise.io/docs/using-the-greynoise-query-language-gnql/a> for further information.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | GNQL query | string | `greynoise query` |
**size** | required | The number of results to return (warning: returning over 1000 results may degrade widget performance) | numeric | |
**exclude_raw** | optional | If true, the raw data will not be included in the response | boolean | |
**quick** | optional | If true, the response will only include the IP address and the classification or trust level | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.query | string | `greynoise query` | metadata.organization:your_organization classification:malicious 8.0.0.0/8 |
action_result.parameter.quick | boolean | | True |
action_result.parameter.exclude_raw | boolean | | False |
action_result.parameter.size | numeric | | 1000 |
action_result.data.\*.data.\*.ip | string | | 8.8.8.8 |
action_result.data.\*.data.\*.trust_level | string | | |
action_result.data.\*.data.\*.visualization | string | | https://viz.greynoise.io/ip/1.1.1.1 |
action_result.data.\*.data.\*.business_service_intelligence.name | string | | |
action_result.data.\*.data.\*.business_service_intelligence.found | boolean | | True False |
action_result.data.\*.data.\*.business_service_intelligence.category | string | | |
action_result.data.\*.data.\*.business_service_intelligence.reference | string | | |
action_result.data.\*.data.\*.business_service_intelligence.description | string | | |
action_result.data.\*.data.\*.business_service_intelligence.explanation | string | | |
action_result.data.\*.data.\*.business_service_intelligence.trust_level | string | | |
action_result.data.\*.data.\*.business_service_intelligence.last_updated | string | | |
action_result.data.\*.data.\*.internet_scanner_intelligence.bot | boolean | | True False |
action_result.data.\*.data.\*.internet_scanner_intelligence.tor | boolean | | True False |
action_result.data.\*.data.\*.internet_scanner_intelligence.vpn | boolean | | True False |
action_result.data.\*.data.\*.internet_scanner_intelligence.tags.\*.id | string | | 23e6932c-e2bd-48cf-80b8-aa98ae9276c4 |
action_result.data.\*.data.\*.internet_scanner_intelligence.tags.\*.name | string | | Open Proxy Scanner |
action_result.data.\*.data.\*.internet_scanner_intelligence.tags.\*.slug | string | | open-proxy-scanner |
action_result.data.\*.data.\*.internet_scanner_intelligence.tags.\*.created | string | | 2020-04-07 |
action_result.data.\*.data.\*.internet_scanner_intelligence.tags.\*.category | string | | activity |
action_result.data.\*.data.\*.internet_scanner_intelligence.tags.\*.intention | string | | malicious |
action_result.data.\*.data.\*.internet_scanner_intelligence.tags.\*.updated_at | string | | 2025-08-06T19:35:47.874643Z |
action_result.data.\*.data.\*.internet_scanner_intelligence.tags.\*.description | string | | IP addresses with this tag have been observed crawling the Internet for unauthenticated web proxies and testing if they are functional. |
action_result.data.\*.data.\*.internet_scanner_intelligence.tags.\*.recommend_block | boolean | | True False |
action_result.data.\*.data.\*.internet_scanner_intelligence.actor | string | | unknown |
action_result.data.\*.data.\*.internet_scanner_intelligence.found | boolean | | True False |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.os | string | | |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.asn | string | | AS45899 |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.rdns | string | | |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.domain | string | | vnpt.vn |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.mobile | boolean | | True False |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.region | string | | Thừa Thiên Huế Province |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.carrier | string | | |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.category | string | | isp |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.latitude | numeric | | 16.4619 |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.longitude | numeric | | 107.5955 |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.datacenter | string | | |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.rdns_parent | string | | |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.sensor_hits | numeric | | 38303 |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.source_city | string | | Huế |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.organization | string | | VNPT Corp |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.sensor_count | numeric | | 5 |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.rdns_validated | boolean | | True False |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.source_country | string | | Vietnam |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.single_destination | boolean | | True False |
action_result.data.\*.data.\*.internet_scanner_intelligence.metadata.source_country_code | string | | VN |
action_result.data.\*.data.\*.internet_scanner_intelligence.raw_data.scan.\*.port | numeric | | 1001 |
action_result.data.\*.data.\*.internet_scanner_intelligence.raw_data.scan.\*.protocol | string | | tcp |
action_result.data.\*.data.\*.internet_scanner_intelligence.raw_data.source.bytes | numeric | | 2054653 |
action_result.data.\*.data.\*.internet_scanner_intelligence.last_seen | string | | 2025-08-07 |
action_result.data.\*.data.\*.internet_scanner_intelligence.spoofable | boolean | | True False |
action_result.data.\*.data.\*.internet_scanner_intelligence.first_seen | string | | 2025-08-06 |
action_result.data.\*.data.\*.internet_scanner_intelligence.vpn_service | string | | |
action_result.data.\*.data.\*.internet_scanner_intelligence.classification | string | | malicious |
action_result.data.\*.data.\*.internet_scanner_intelligence.last_seen_timestamp | string | | 2025-08-07 00:00:35 |
action_result.data.\*.request_metadata.count | numeric | | 1727718 |
action_result.data.\*.request_metadata.query | string | | classification:malicious |
action_result.data.\*.request_metadata.scroll | string | | FGluY2x1ZGVfY29udGV4dF91dWlkDnF1ZXJ5VGhlbkZldGNoAhZmeVI3dE1WUVFxQ216bGNuR3B0VnJ3AAAAAAQVqCIWZF9Tdzc3Yk1Td1MwRXRPcFFwR1NOURZpdUFkYmlxNVJWQ0otbG5hR1Q5NjBBAAAAAANxuBgWUHFxZDZVbHJSb2VLTE05eWdFSFV4QQ== |
action_result.data.\*.request_metadata.message | string | | |
action_result.data.\*.request_metadata.complete | boolean | | True False |
action_result.data.\*.request_metadata.adjusted_query | string | | (classification:malicious) last_seen:90d |
action_result.data.\*.data.\*.internet_scanner_intelligence.raw_data.ja3.\*.port | numeric | | 8001 |
action_result.data.\*.data.\*.internet_scanner_intelligence.raw_data.ja3.\*.fingerprint | string | | 19e29534fd49dd27d09234e639c4057e |
action_result.data.\*.actor | string | | Shodan.io |
action_result.data.\*.classification | string | | benign malicious |
action_result.data.\*.first_seen | string | | 2020-12-25 |
action_result.data.\*.ip | string | `ip` | 8.8.8.8 |
action_result.data.\*.last_seen | string | | 2020-12-25 |
action_result.data.\*.metadata.\* | string | | { "country":"United States" "country_code":"US" "city":"Seattle" "organization":"Org. Name" "rdns":"crawl-66-249-79-17.testbot.com" "asn":"AS521" "tor":false "category":"education" "os":"Windows 7/8" } |
action_result.data.\*.raw_data.\* | string | | { "scan":[ 0:{ "port":80 "protocol":"TCP" } ] "web":{ "paths":[ 0:"/robots.txt" ] "useragents":[ 0:"test/5.0 (compatible; testbot/2.1; +http://www.test.com/bot.html)" ] } "ja3":[ 0:{ "fingerprint":"c3a6cf0bf2e690ac8e1ecf6081f17a50" "port":443 } ] } |
action_result.data.\*.seen | boolean | | True False |
action_result.data.\*.tags.\* | string | | Mirai Telnet Worm |
action_result.status | string | | success failed |
action_result.message | string | | GNQL Query action successfully completed |
action_result.summary | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup ips'

Lookup IPs using GreyNoise API Multi Quick Check Endpoint (comma-separated, limit 500 per request)

Type: **investigate** \
Read only: **True**

Returns quick check information for multiple IPs.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ips** | required | IPs to query(comma-separated) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ips | string | | 8.8.8.8,8.8.4.4 |
action_result.data.\*.ip | string | `ip` | 8.8.8.8 |
action_result.data.\*.trust_level | string | | 1 - Reasonably Ignore |
action_result.data.\*.visualization | string | `url` | https://viz.greynoise.io/ip/1.1.1.1 |
action_result.data.\*.business_service_intelligence.found | boolean | | False True |
action_result.data.\*.business_service_intelligence.trust_level | string | | trusted |
action_result.data.\*.internet_scanner_intelligence.found | boolean | | True False |
action_result.data.\*.internet_scanner_intelligence.classification | string | | malicious benign |
action_result.status | string | | success failed |
action_result.message | string | | Lookup IP action successfully completed |
action_result.summary | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

Get details on a specific GNQL query

Type: **ingest** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Parameter ignored in this app | numeric | |
**end_time** | optional | Parameter ignored in this app | numeric | |
**container_count** | optional | Maximum number of results to return for the on poll action | numeric | |
**artifact_count** | optional | Parameter ignored in this app | numeric | |

#### Action Output

No Output

## action: 'noise ip timeline'

GreyNoise IP Timeline lookup for events matching a specific field

Type: **investigate** \
Read only: **True**

The GreyNoise IP Timeline shows historical data on an IP address filtered by a specific field.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to get timeline information | string | `ip` |
**days** | optional | Number of days to show data for (Default: 30) | numeric | |
**field** | required | Field over which to show activity breakdown | string | |
**granularity** | optional | Granularity of activity date ranges .This can be either in hour(1h) or in day(1d) (Default: 1d) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string | `ip` | 8.8.8.8 |
action_result.parameter.days | numeric | | 30 |
action_result.parameter.field | string | | classification |
action_result.parameter.granularity | string | | 4d |
action_result.data.\*.metadata.ip | string | `ip` | 8.8.8.8 |
action_result.data.\*.ip | string | | 8.8.8.8 |
action_result.data.\*.metadata.field | string | | classification |
action_result.data.\*.metadata.first_seen | string | | 2020-02-01 |
action_result.data.\*.metadata.start | string | | 2025-05-08T04:46:22.037900129Z |
action_result.data.\*.metadata.end | string | | 2025-08-06T04:46:22.037900129Z |
action_result.data.\*.metadata.granularity | string | | 4d |
action_result.data.\*.metadata.metric | string | | count |
action_result.data.\*.results.\*.data | numeric | | 1 |
action_result.data.\*.results.\*.label | string | | suspicious malicious |
action_result.data.\*.results.\*.timestamp | string | | 2025-06-25T00:00:00Z |
action_result.status | string | | success failed |
action_result.message | string | | Lookup IP Timeline action successfully completed |
action_result.summary | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get cve details'

Retrieve details about a specific Common Vulnerabilities and Exposures (CVE)

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cve_id** | required | The CVE ID to query (e.g., CVE-2024-12345) | string | `cve` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.cve_id | string | `cve` | CVE-2024-12345 |
action_result.data.\*.id | string | | CVE-2024-12345 |
action_result.data.\*.details.vendor | string | | Fortinet |
action_result.data.\*.details.product | string | | Multiple Products |
action_result.data.\*.details.cve_cvss_score | numeric | | 9.8 |
action_result.data.\*.details.vulnerability_name | string | | Fortinet Multiple Products Authentication Bypass Vulnerability |
action_result.data.\*.details.published_to_nist_nvd | boolean | | True False |
action_result.data.\*.details.vulnerability_description | string | | An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests. |
action_result.data.\*.timeline.cve_published_date | string | | 2022-10-18T14:15:09Z |
action_result.data.\*.timeline.cisa_kev_date_added | string | | 2022-10-11T00:00:00Z |
action_result.data.\*.timeline.cve_last_updated_date | string | | 2025-02-19T19:37:18Z |
action_result.data.\*.timeline.first_known_published_date | string | | 2022-10-10T00:00:00Z |
action_result.data.\*.exploitation_stats.number_of_available_exploits | numeric | | 30 |
action_result.data.\*.exploitation_stats.number_of_botnets_exploiting_vulnerability | numeric | | |
action_result.data.\*.exploitation_stats.number_of_threat_actors_exploiting_vulnerability | numeric | | 4 |
action_result.data.\*.exploitation_details.epss_score | numeric | | 0.94427 |
action_result.data.\*.exploitation_details.attack_vector | string | | NETWORK |
action_result.data.\*.exploitation_details.exploit_found | boolean | | True False |
action_result.data.\*.exploitation_details.exploitation_registered_in_kev | boolean | | True False |
action_result.data.\*.exploitation_activity.activity_seen | boolean | | True False |
action_result.data.\*.exploitation_activity.benign_ip_count_1d | numeric | | |
action_result.data.\*.exploitation_activity.threat_ip_count_1d | numeric | | 4 |
action_result.data.\*.exploitation_activity.benign_ip_count_10d | numeric | | |
action_result.data.\*.exploitation_activity.benign_ip_count_30d | numeric | | |
action_result.data.\*.exploitation_activity.threat_ip_count_10d | numeric | | 12 |
action_result.data.\*.exploitation_activity.threat_ip_count_30d | numeric | | 22 |
action_result.status | string | | success failed |
action_result.message | string | | Get CVE Details action successfully completed |
action_result.summary | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
