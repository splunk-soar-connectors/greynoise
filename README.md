[comment]: # "Auto-generated SOAR connector documentation"
# GreyNoise for SOAR

Publisher: GreyNoise  
Connector Version: 2.3.1  
Product Vendor: GreyNoise  
Product Name: GreyNoise  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.3.0  

This app provides investigative capabilities using the GreyNoise plugin

[comment]: # " File: README.md"
[comment]: # ""
[comment]: # "  Copyright (c) GreyNoise, 2019-2023."
[comment]: # ""
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
## Playbook Backward Compatibility

-   Version 2.0.0 of this application is a complete rewrite and is not backward compatible with
    version 1.0.0. Hence, it is requested to the end-user to please update their existing playbooks
    by re-inserting | modifying | deleting the corresponding action blocks to ensure the correct
    functioning of the playbooks created on the earlier versions of the app. If the end-user does
    not want to upgrade their playbooks, they can remain on or downgrade to the old version(v1.0.0).

## Description

The GreyNoise Enrichment plugin for Phantom enriches observables to identify activity associated
with mass-internet scanning, creating more time to investigate other higher priority observables.
This enrichment provides context into IP behavior: intent, tags, first seen, last seen, geo-data,
ports, OS, and JA3.  
  
The GreyNoise Enrichment plugin for Phantom requires an API key. Set up an account to receive an API
key and find GreyNoise documentation here: <https://docs.greynoise.io/>

## Actions

#### lookup ip

Check to see if a given IP has been seen by GreyNoise engaging in internet scanning behavior.

#### riot lookup ip

Identifies IPs from known benign services and organizations that commonly cause false positives.

#### community lookup ip

An action requiring at least a free community API key to query IPs in the GreyNoise dataset and
retrieve a subset of the IP reputation data returned by the lookup ip and lookup reputation actions.
A free API key can be obtained at <https://www.greynoise.io/viz/signup>

#### lookup ips

Check whether IP addresses in a set have been seen engaging in internet scanning behavior. This
action is similar to *lookup ip* except that it processes more than one IP at a time. IPs should be
comma-separated.

#### ip reputation

Delivers full IP context: time ranges, IP metadata (network owner, ASN, reverse DNS pointer,
country), associated actors, activity tags, and raw port scan and web request information.

#### similar noise ips

Uses the GreyNoise Similarity feature to identify other internet scanning IPs that have similar
features in use.

#### noise ip timeline

Uses the GreyNoise IP Timeline feature to retrieve a daily timeline of scanning behavior associated
with the IP.

#### gnql query

GreyNoise Query Language (GNQL) uses Lucene deep under the hood. GNQL enables users to make complex
and one-off queries against the GreyNoise dataset.  
For more information, please visit: <https://docs.greynoise.io/reference/gnqlquery-1>

#### on poll

Retrieves GNQL query results on a set interval. The default number of results returned is 25.  
Notes:

-   The value provided in the configuration parameter "on_poll_size" will only be considered for
    scheduled or interval polling. For manual polling, the value provided in the "container_count"
    will be considered.

-   The on poll action will spawn a container for each result returned. Phantom performance may be
    degraded if an overly large query is used.

-   Potentially useful queries may include ones that limit results to assets owned by your
    organization, such as:

-   -   metadata.organization:your_organization classification:malicious
    -   8.8.8.0/30 (replace with your address block) classification:malicious

-   To test your query or to learn more about GNQL queries, please visit
    <https://docs.greynoise.io/reference/gnqlquery-1>

#### test connectivity

Test connectivity to GreyNoise. Requires a valid paid or free community API key.

## Legal

For terms and legal information, please visit <https://greynoise.io/terms>

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the GreyNoise server. Below are the default
ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a GreyNoise asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** |  required  | password | API Key for GreyNoise
**on_poll_query** |  optional  | string | GNQL query to use for the on poll action
**on_poll_size** |  optional  | numeric | The number of results to return for the interval/schedule poll
**license_type** |  optional  | string | GreyNoise license type

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration  
[lookup ip](#action-lookup-ip) - Lookup IP using GreyNoise API Quick Check Endpoint  
[riot lookup ip](#action-riot-lookup-ip) - Lookup IP using GreyNoise's RIOT endpoint  
[ip reputation](#action-ip-reputation) - Get full GreyNoise reputation and context for a specific IP  
[gnql query](#action-gnql-query) - Use the GreyNoise Query Language to run a query  
[lookup ips](#action-lookup-ips) - Lookup IPs using GreyNoise API Multi Quick Check Endpoint (comma-separated, limit 500 per request)  
[on poll](#action-on-poll) - Get details on a specific GNQL query  
[community lookup ip](#action-community-lookup-ip) - Lookup IP using GreyNoise's free community endpoint  
[similar noise ips](#action-similar-noise-ips) - Lookup Similar internet scanner IP using GreyNoise's IP Similarity tool  
[noise ip timeline](#action-noise-ip-timeline) - Lookup Similar internet scanner IP using GreyNoise's IP Similarity tool  

## action: 'test connectivity'
Validate the asset configuration for connectivity using the supplied configuration

Type: **test**  
Read only: **True**

Tests the connection to the paid GreyNoise API.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup ip'
Lookup IP using GreyNoise API Quick Check Endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  |   71.6.135.131 
action_result.data.\*.code | string |  |   0x00  0x01 
action_result.data.\*.code_message | string |  |   The IP has never been observed scanning the Internet  The IP has been observed by the GreyNoise sensor network 
action_result.data.\*.noise | boolean |  |   True  False 
action_result.data.\*.riot | boolean |  |   True  False 
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'riot lookup ip'
Lookup IP using GreyNoise's RIOT endpoint

Type: **investigate**  
Read only: **True**

RIOT identifies IPs from known benign services and organizations that commonly cause false positives in network security and threat intelligence products. The collection of IPs in RIOT is continually curated and verified to provide accurate results.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- |----------| --------------
action_result.parameter.ip | string | `ip`     |   71.6.135.131 
action_result.data.\*.category | string |          |   public_dns 
action_result.data.\*.description | string |          |   Global domain name system (DNS) resolution service. 
action_result.data.\*.explanation | string |          |   Public DNS services are used as alternatives to ISP's name servers. You may see devices on your network communicating with Public DNS over port XX/TCP or XX/UDP to resolve DNS lookups. 
action_result.data.\*.last_updated | string |          |   2021-05-26T17:55:35Z
action_result.data.\*.name | string |          |   Public DNS 
action_result.data.\*.reference | string | `url`    |   https://developers.google.com/speed/public-dns/docs/isp#alternative 
action_result.data.\*.riot | boolean |          |   true
action_result.data.\*.trust_level | string |          |   "1"
action_result.status | string |          |   success  failed 
action_result.message | string |          |  
action_result.summary | string |          |  
summary.total_objects | numeric |          |   1 
summary.total_objects_successful | numeric |          |   1   

## action: 'ip reputation'
Get full GreyNoise reputation and context for a specific IP

Type: **investigate**  
Read only: **True**

Get more information about a given IP address. Returns time ranges, IP metadata (network owner, ASN, reverse DNS pointer, country), associated actors, activity tags, raw port scan, and web request information.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  |   71.6.135.131 
action_result.data.\*.actor | string |  |   Shodan.io 
action_result.data.\*.bot | boolean |  |   True  False 
action_result.data.\*.classification | string |  |   benign  malicious 
action_result.data.\*.cve.\* | string |  |   CVE-2021-10234  CVE-2023-13435 
action_result.data.\*.first_seen | string |  |   2020-12-25 
action_result.data.\*.last_seen | string |  |   2020-12-25 
action_result.data.\*.metadata.\* | string |  |   "{\n\"country\":\"United States\"\n\"country_code\":\"US\"\n\"city\":\"Seattle\"\n\"organization\":\"Org. Name\"\n\"rdns\":\"crawl-66-249-79-17.testbot.com\"\n\"asn\":\"AS521\"\n\"tor\":false\n\"category\":\"education\"\n\"os\":\"Windows 7/8\"\n}"
action_result.data.\*.metadata.asn | string |  |   AS12345
action_result.data.\*.metadata.category | string |  |   isp
action_result.data.\*.metadata.city | string |  |   Madrid
action_result.data.\*.metadata.destination_countries.\* | string |  |   Spain Turkey
action_result.data.\*.metadata.destination_country_codes.\* | string |  |   ES TR
action_result.data.\*.metadata.organization | string |  |   Acme, Inc.
action_result.data.\*.metadata.os | string |  |   Linux 3
action_result.data.\*.metadata.rdns | string |  |   bot.acme.lcl
action_result.data.\*.metadata.region | string |  |   Madrid
action_result.data.\*.metadata.source_country | string |  |   Spain
action_result.data.\*.metadata.source_country_code | string |  |   ES
action_result.data.\*.metadata.tor | boolen |  |   TRUE FALSE
action_result.data.\*.raw_data.\* | string |  |   {\n\"scan\":[\n0:{\n\"port\":80\n\"protocol\":\"TCP\"\n}\n]\n\"web\":{\n\"paths\":[\n0:\"/robots.txt\"\n]\n\"useragents\":[\n0:\"test/5.0 (compatible; testbot/2.1; +http://www.test.com/bot.html)\"\n]\n}\n\"ja3\":[\n0:{\n\"fingerprint\":\"c3a6cf0bf2e690ac8e1ecf6081f17a50\"\n\"port\":443\n}\n]\n}
action_result.data.\*.raw_data.hassh.\* | string |  |   [{\n\"fingerprint\":\"c3a6cf0bf2e690ac8e1ecf6081f17a50\"\n\"port\":443\n}]
action_result.data.\*.raw_data.ja3.\* | string |  |   [{\n\"fingerprint\":\"c3a6cf0bf2e690ac8e1ecf6081f17a50\"\n\"port\":443\n}]
action_result.data.\*.raw_data.scan.\* | string |  |   [\n{\n\"port\":23,\n\"protocol\":\"TCP\"\n},\n{\n\"port\":80,\n\"protocol\":\"TCP\"\n},\n{\n\"port\":8080,\n\"protocol\":\"TCP\"\n}\n]
action_result.data.\*.raw_data.web.\* | string |  |   {\n\"paths\":[\n\"/\"\n],\n\"useragents\":[\n\"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\"\n]\n}
action_result.data.\*.seen | boolean |  |   True  False 
action_result.data.\*.spoofable | boolean |  |   True  False 
action_result.data.\*.tags.\* | string |  |   Mirai  Telnet Worm 
action_result.data.\*.vpn | boolean |  |   True  False 
action_result.data.\*.vpn_service | string |  |   PRETTY_VPN
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'gnql query'
Use the GreyNoise Query Language to run a query

Type: **investigate**  
Read only: **True**

Please refer to <a target="_blank" rel="noopener noreferrer" href="https://docs.greynoise.io/reference/gnqlquery-1">https://docs.greynoise.io/reference/gnqlquery-1/a> for further information.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | GNQL query | string |  `greynoise query` 
**size** |  required  | The number of results to return (warning: returning over 1000 results may degrade widget performance) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.query | string |  `greynoise query`  |   metadata.organization:your_organization classification:malicious  8.0.0.0/8 
action_result.parameter.size | numeric |  |   1000 
action_result.data.\*.actor | string |  |   Shodan.io 
action_result.data.\*.classification | string |  |   benign  malicious 
action_result.data.\*.first_seen | string |  |   2020-12-25 
action_result.data.\*.ip | string |  `ip`  |   71.6.135.131 
action_result.data.\*.last_seen | string |  |   2020-12-25 
action_result.data.\*.metadata.\* | string |  |   {\n\"country\":\"United States\"\n\"country_code\":\"US\"\n\"city\":\"Seattle\"\n\"organization\":\"Org. Name\"\n\"rdns\":\"crawl-66-249-79-17.testbot.com\"\n\"asn\":\"AS521\"\n\"tor\":false\n\"category\":\"education\"\n\"os\":\"Windows 7/8\"\n}
action_result.data.\*.raw_data.\* | string |  |   {\n\"scan\":[\n0:{\n\"port\":80\n\"protocol\":\"TCP\"\n}\n]\n\"web\":{\n\"paths\":[\n0:\"/robots.txt\"\n]\n\"useragents\":[\n0:\"test/5.0 (compatible; testbot/2.1; +http://www.test.com/bot.html)\"\n]\n}\n\"ja3\":[\n0:{\n\"fingerprint\":\"c3a6cf0bf2e690ac8e1ecf6081f17a50\"\n\"port\":443\n}\n]\n}
action_result.data.\*.seen | boolean |  |   True  False 
action_result.data.\*.tags.\* | string |  |   Mirai  Telnet Worm 
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'lookup ips'
Lookup IPs using GreyNoise API Multi Quick Check Endpoint (comma-separated, limit 500 per request)

Type: **investigate**  
Read only: **True**

Returns quick check information for multiple IPs.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ips** |  required  | IPs to query, comma-separated list allowed | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ips | string |  |   71.6.135.131,111.111.111.111 
action_result.data.\*.code | string |  |   0x00  0x01 
action_result.data.\*.code_message | string |  |   The IP has never been observed scanning the Internet  The IP has been observed by the GreyNoise sensor network 
action_result.data.\*.noise | boolean |  |   True  False 
action_result.data.\*.riot | boolean |  |   True  False 
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'on poll'
Get details on a specific GNQL query

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** |  optional  | Parameter ignored in this app | numeric | 
**end_time** |  optional  | Parameter ignored in this app | numeric | 
**container_count** |  optional  | Maximum number of results to return for the on poll action | numeric | 
**artifact_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'community lookup ip'
Lookup IP using GreyNoise's free community endpoint

Type: **investigate**  
Read only: **True**

The Community API provides community users with a free tool to query IPs in the GreyNoise dataset and retrieve a subset of the full IP context data returned by the IP Lookup API.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  |   71.6.135.131 
action_result.data.\*.classification | string |  |   benign  malicious 
action_result.data.\*.last_seen | string |  |   2020-01-01 
action_result.data.\*.link | string |  `url`  |   https://viz.greynoise.io/riot/1.2.3.4 
action_result.data.\*.message | string |  |   Success  You have hit your daily rate limit of 100 requests per day. Please create a free account or upgrade your plan at https://greynoise.io/pricing. 
action_result.data.\*.name | string |  |   Cloudflare 
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'similar noise ips'
Lookup Similar internet scanner IP using GreyNoise's IP Similarity tool

Type: **investigate**  
Read only: **True**

The GreyNoise IP Similarity tool allows for analysts to identify IP addresses within the GreyNoise internet scanning dataset that are using a similar scanning profile.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to find Similar IPs for | string |  `ip` 
**min_score** |  required  | The minimum score to return matches for, recommended is 90. | numeric | 
**limit** |  required  | The maximum number of similar IP results to return. | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  |   71.6.135.131 
action_result.parameter.min_score | numeric |  |   90 
action_result.parameter.limit | numeric |  |   50 
action_result.data.\*.actor | string |  |   Shodan.io  Censys 
action_result.data.\*.classification | string |  |   benign  malicious 
action_result.data.\*.fist_seen | string |  |   2020-01-01 
action_result.data.\*.last_seen | string |  |   2020-01-01 
action_result.data.\*.asn | string |  |   AS2345  AS62432 
action_result.data.\*.city | string |  |   New York  Houston 
action_result.data.\*.country | string |  |   United States  Canada 
action_result.data.\*.country_code | string |  |   US  CA 
action_result.data.\*.organization | string |  |   Microsoft  Acme, Inc 
action_result.data.\*.similar_ips.\* | string |  |   {
"country":"United States"
"country_code":"US"
"city":"Seattle"
"organization":"Org. Name"
"rdns":"crawl-66-249-79-17.testbot.com"
"asn":"AS521"
"tor":false
"category":"education"
"os":"Windows 7/8"
} 
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'noise ip timeline'
Lookup Similar internet scanner IP using GreyNoise's IP Similarity tool

Type: **investigate**  
Read only: **True**

The GreyNoise IP Similarity tool allows for analysts to identify IP addresses within the GreyNoise internet scanning dataset that are using a similar scanning profile.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to get timeline information | string |  `ip` 
**days** |  required  | The maximum number of days to pull timeline data | numeric | 
**limit** |  required  | The maximum number of results to return. | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  |   71.6.135.131 
action_result.parameter.days | numeric |  |   30 
action_result.parameter.limit | numeric |  |   50 
action_result.data.\*.metadata.\* | string |  |   {\n\"country\":\"United States\"\n\"country_code\":\"US\"\n\"city\":\"Seattle\"\n\"organization\":\"Org. Name\"\n\"rdns\":\"crawl-66-249-79-17.testbot.com\"\n\"asn\":\"AS521\"\n\"tor\":false\n\"category\":\"education\"\n\"os\":\"Windows 7/8\"\n}
action_result.data.\*.activity.\* | string |  |   {\n\"country\":\"United States\"\n\"country_code\":\"US\"\n\"city\":\"Seattle\"\n\"organization\":\"Org. Name\"\n\"rdns\":\"crawl-66-249-79-17.testbot.com\"\n\"asn\":\"AS521\"\n\"tor\":false\n\"category\":\"education\"\n\"os\":\"Windows 7/8\"\n}
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 