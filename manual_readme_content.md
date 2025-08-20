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
