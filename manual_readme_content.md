[comment]: # " File: README.md"
[comment]: # ""
[comment]: # "  Copyright (c) GreyNoise, 2019-2022."
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
