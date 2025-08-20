# File: greynoise_webhook.py
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
"""
GreyNoise Webhook Handler for SOAR Platform.

This module handles incoming webhooks from GreyNoise,
processes the alert and feed data, and creates SOAR containers and artifacts.
"""

import json
import logging
from datetime import datetime
from typing import Any, Optional, Union

from phantom_common.install_info import get_verify_ssl_setting

from greynoise_consts import *


# Initialize logging
logger = logging.getLogger("app_interface")


def create_error_response(status_code: int, error: str, message: str) -> dict[str, Any]:
    """
    Create a standardized error response.

    Args:
        status_code: HTTP status code
        error: Short error description
        message: Detailed error message

    Returns:
        A dictionary with the response status code, headers and content
    """
    return {"status_code": status_code, "headers": [CONTENT_TYPE_HEADER], "content": json.dumps({"error": error, "message": message})}


def create_success_response(container_id: int, artifact_ids: list[int]) -> dict[str, Any]:
    """
    Create a success response for the webhook.

    Args:
        container_id: ID of created container
        artifact_ids: List of IDs of all created artifacts

    Returns:
        A dictionary with the response status code, headers and content
    """
    return {
        "status_code": HTTP_OK,
        "headers": [CONTENT_TYPE_HEADER],
        "content": json.dumps({"container_id": container_id, "artifact_ids": artifact_ids, "status": "success"}),
    }


def validate_request(method: str, body: str) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]]]:
    """
    Validate the incoming webhook request method and body.

    Args:
        method: HTTP method used in the request
        body: Request body as a string

    Returns:
        Tuple containing (parsed JSON data, error response or None)
    """
    # Validate request method
    if method.lower() != "post":
        return None, create_error_response(HTTP_METHOD_NOT_ALLOWED, "Method not allowed", "Only POST requests are supported")

    # Parse and validate the incoming JSON data
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in request body: {e}")
        return None, create_error_response(HTTP_BAD_REQUEST, "Invalid JSON", f"Request body contains invalid JSON: {e}")

    # Validate expected data format
    if not data:
        return None, create_error_response(HTTP_BAD_REQUEST, "Empty data", "Request body contains empty JSON data")

    return data, None


def format_utc_timestamp(iso_timestamp: str, mode: str = "datetime") -> str:
    """
    Format an ISO timestamp in UTC into a human-readable format.

    Args:
        iso_timestamp: Timestamp in ISO format
        mode: 'datetime' for full timestamp, 'date' for date only

    Returns:
        A formatted timestamp string

    Raises:
        ValueError: If there's an issue parsing the timestamp
    """
    if not iso_timestamp:
        logger.warning("Empty timestamp provided to format_utc_timestamp")
        return "Unknown timestamp"

    try:
        if "." in iso_timestamp:
            # Handle timestamp with nanoseconds
            if len(iso_timestamp.split(".")[1]) > 6:
                # Trim nanoseconds to 6 digits
                iso_timestamp = iso_timestamp[: iso_timestamp.index(".") + 7] + "Z"
            dt = datetime.strptime(iso_timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            dt = datetime.strptime(iso_timestamp, "%Y-%m-%dT%H:%M:%SZ")

        if mode == "date":
            return dt.strftime("%Y-%m-%d (UTC)")
        elif mode == "datetime":
            return dt.strftime("%Y-%m-%d %H:%M:%S (UTC)")
        else:
            raise ValueError(f"Unsupported mode: {mode}")

    except ValueError as e:
        logger.error(f"Error formatting timestamp '{iso_timestamp}': {e}")
        raise ValueError(f"Invalid timestamp format: {e}")


def determine_severity(classification: str) -> str:
    """
    Determine the severity based on the classification.

    Args:
        classification: The classification string from the alert

    Returns:
        A severity string (high, medium, or low)
    """
    return SEVERITY_MAP.get(classification.lower())


def convert_to_cef_fields(data: dict[str, Any]) -> dict[str, Any]:
    """
    Convert the feed data to CEF fields.

    Args:
        data: The data to convert

    Returns:
        A dictionary containing the CEF fields
    """
    cef_fields = {k.split("_")[0] + "".join(word.capitalize() for word in k.split("_")[1:]): v for k, v in data.items()}
    return cef_fields


def convert_activity_state(state_data: Optional[dict[str, Any]]) -> str:
    """
    Convert boolean activity_seen to human-readable format

    Args:
        state_data: Dictionary containing activity state information

    Returns:
        String indicating activity status
    """
    if not state_data:
        logger.warning("Empty state data provided to convert_activity_state")
        return "Unknown activity status"

    return "Recent activity" if state_data.get("activity_seen", False) else "No recent activity"


def create_alert_container(alert_metadata: dict[str, Any], alert_timestamp: str, soar_rest_client: Any, container_label: str) -> int:
    """
    Create and save a container object in the SOAR platform.

    Args:
        alert_metadata: Alert metadata from the alert
        alert_timestamp: Timestamp of the alert
        soar_rest_client: Client for interacting with SOAR platform
        container_label: The label for the container

    Returns:
        The ID of the created container

    Raises:
        Exception: If container creation fails
    """
    try:
        # Generate container data
        alert_name = alert_metadata.get("name", "Unknown Alert")
        alert_type = alert_metadata.get("type", "UNKNOWN").upper()
        formatted_timestamp = format_utc_timestamp(alert_timestamp)
        container_name = f"GreyNoise Alert: {alert_name}: {alert_type}: {formatted_timestamp}"
        logger.info(f"Creating container for GreyNoise alert: {container_name}")

        container = {
            "name": container_name,
            "description": f"GreyNoise alert for {alert_name}",
            "label": container_label,
            "tags": [GREYNOISE_ALERT_TAG],
        }

        # Send API request to create container
        response = soar_rest_client.session.post(
            f"{soar_rest_client.base_url}/container",
            json=container,
            verify=get_verify_ssl_setting(),
        )

        # Handle the response
        response.raise_for_status()
        container_id = response.json().get("id")
        logger.info(f"Container created for GreyNoise alert: {container_id}")

        return container_id
    except Exception as e:
        logger.error(f"Failed to create alert container: {e}")
        raise


def create_alert_artifacts(
    container_id: int, alert_metadata: dict[str, Any], alert_ip_data: list[dict[str, Any]], soar_rest_client: Any, container_label: str
) -> list[int]:
    """
    Create and save artifacts on the SOAR platform.

    Args:
        container_id: ID of the parent container
        alert_metadata: Alert metadata from the alert
        alert_ip_data: Data for each IP in the alert
        soar_rest_client: Client for interacting with SOAR platform
        container_label: The label of the container

    Returns:
        The IDs of the created artifacts

    Raises:
        Exception: If artifact creation fails
    """
    artifact_ids = []
    for ip_data in alert_ip_data:
        try:
            logger.info(f"Creating artifact for GreyNoise alert: {ip_data.get('ip')}")
            artifact = {
                "name": f"IP Artifact: {ip_data.get('ip')}",
                "label": container_label,
                "severity": determine_severity(ip_data.get("classification")),
                "container_id": container_id,
                "run_automation": True,
                "cef": {
                    "alert": convert_to_cef_fields(alert_metadata),
                    "ip": ip_data.get("ip"),
                    "classification": ip_data.get("classification"),
                    "sourceAddress": ip_data.get("ip"),
                },
                "cef_types": {
                    "ip": ["ip"],
                    "sourceAddress": ["ip"],
                },
                "tags": [GREYNOISE_ALERT_TAG],
            }

            # Send API request to create artifact
            response_artifact = soar_rest_client.session.post(
                f"{soar_rest_client.base_url}/artifact",
                json=artifact,
                verify=get_verify_ssl_setting(),
            )

            # Handle the response
            response_artifact.raise_for_status()
            artifact_id = response_artifact.json().get("id")
            artifact_ids.append(artifact_id)

        except Exception as e:
            logger.error(f"Failed to create artifact for IP {ip_data.get('ip')}: {e}")
            # Continue with other IPs even if one fails
            continue

    logger.info(f"Artifacts created for GreyNoise alert: {artifact_ids}")
    return artifact_ids


def process_alert(alert: dict[str, Any], soar_rest_client: Any, container_label: str) -> tuple[int, list[int]]:
    """
    Process a single alert from the webhook data.

    Args:
        alert: The alert data to process
        soar_rest_client: Client for interacting with SOAR platform
        container_label: The label of the container

    Returns:
        Tuple containing (container_id, artifact_ids)
    """
    # Extract critical fields
    alert_timestamp = alert.get("timestamp")
    alert_metadata = alert.get("alert", {})
    alert_ip_data = alert.get("data", [])

    # Add links to metadata
    alert_metadata.update({"viz_link": alert.get("viz_link"), "query_link": alert.get("query_link"), "alert_link": alert.get("alert_link")})

    # Create container and get container ID
    container_id = create_alert_container(alert_metadata, alert_timestamp, soar_rest_client, container_label)

    # Create artifacts and get artifact IDs
    artifact_ids = create_alert_artifacts(container_id, alert_metadata, alert_ip_data, soar_rest_client, container_label)

    return container_id, artifact_ids


def create_feed_container(feed_timestamp: str, soar_rest_client: Any, container_label: str) -> int:
    """
    Create and save a container object in the SOAR platform.

    Args:
        feed_timestamp: Timestamp of the feed
        soar_rest_client: Client for interacting with SOAR platform
        container_label: The label of the container

    Returns:
        The ID of the created container

    Raises:
        Exception: If container creation fails
    """
    try:
        # Extract the date from the timestamp
        date = format_utc_timestamp(feed_timestamp, mode="date")
        container_name = f"GreyNoise Feed: {date}"

        # Get existing containers for the date
        logger.info(f"Check if container exists for GreyNoise feed for date: {date}")
        response = soar_rest_client.session.get(
            f"{soar_rest_client.base_url}/container",
            params={"_filter_name": f'"{container_name}"', "_filter_label": f'"{container_label}"'},
            verify=get_verify_ssl_setting(),
        )
        response.raise_for_status()

        if response.json().get("count") > 0:
            # Container with same name exists in provided label
            container_id = response.json().get("data")[-1].get("id")  # Return the last container ID, which will be the most recent
            logger.info(f"Using existing container for GreyNoise feed for date: {date}, ID: {container_id}")
            return container_id

        logger.info(f"Creating new container for GreyNoise feed for date: {date}")
        # Create a new container if none exists for the date
        container = {
            "name": container_name,
            "description": f"GreyNoise feed for date: {date}",
            "label": container_label,
            "tags": [GREYNOISE_FEED_TAG],
        }
        response = soar_rest_client.session.post(
            f"{soar_rest_client.base_url}/container",
            json=container,
            verify=get_verify_ssl_setting(),
        )
        response.raise_for_status()
        container_id = response.json().get("id")
        logger.info(f"Container created for GreyNoise feed for date: {date}, ID: {container_id}")
        return container_id

    except Exception as e:
        logger.error(f"Failed to create or find feed container: {e}")
        raise


# Refactored artifact creation functions to reduce code duplication
def _create_artifact_base(container_id: int, name: str, container_label: str, severity: Optional[str], tags: list[str]) -> dict[str, Any]:
    """
    Create the base structure for an artifact.

    Args:
        container_id: ID of the parent container
        name: Name of the artifact
        container_label: Label of the container
        severity: Severity level (optional)
        tags: List of tags to apply

    Returns:
        Base artifact dictionary
    """
    artifact = {
        "name": name,
        "label": container_label,
        "container_id": container_id,
        "run_automation": True,
        "tags": tags,
    }

    if severity:
        artifact["severity"] = severity

    return artifact


def create_feed_ip_artifact(container_id: int, feed: dict[str, Any], soar_rest_client: Any, container_label: str) -> int:
    """
    Create and save an IP artifact on the SOAR platform.

    Args:
        container_id: ID of the parent container
        feed: Feed data to process
        soar_rest_client: Client for interacting with SOAR platform
        container_label: The label of the container

    Returns:
        The ID of the created artifact

    Raises:
        Exception: If artifact creation fails
    """
    try:
        formatted_timestamp = format_utc_timestamp(feed.get("timestamp"))
        ip = feed.get("ip", "unknown")

        # Create base artifact
        artifact = _create_artifact_base(
            container_id=container_id,
            name=f"IP Artifact: {ip}",
            container_label=container_label,
            severity=determine_severity(feed.get("new_state")),
            tags=[GREYNOISE_FEED_TAG, GREYNOISE_FEED_IP_TAG],
        )

        # Add IP-specific CEF fields
        artifact["cef"] = {
            "ip": ip,
            "oldClassification": feed.get("old_state"),
            "newClassification": feed.get("new_state"),
            "sourceAddress": ip,
            "timestamp": formatted_timestamp,
        }

        artifact["cef_types"] = {
            "ip": ["ip"],
            "sourceAddress": ["ip"],
        }

        logger.info(f"Creating artifact for GreyNoise feed for IP: {ip}")
        response = soar_rest_client.session.post(
            f"{soar_rest_client.base_url}/artifact",
            json=artifact,
            verify=get_verify_ssl_setting(),
        )
        response.raise_for_status()
        artifact_id = response.json().get("id")
        logger.info(f"Artifact created for GreyNoise feed for IP: {ip}, ID: {artifact_id}")
        return artifact_id

    except Exception as e:
        logger.error(f"Failed to create IP feed artifact: {e}")
        raise


def create_feed_cve_artifact(container_id: int, feed: dict[str, Any], soar_rest_client: Any, container_label: str) -> int:
    """
    Create and save a CVE artifact on the SOAR platform.

    Args:
        container_id: ID of the parent container
        feed: Feed data to process
        soar_rest_client: Client for interacting with SOAR platform
        container_label: The label of the container

    Returns:
        The ID of the created artifact

    Raises:
        Exception: If artifact creation fails
    """
    try:
        formatted_timestamp = format_utc_timestamp(feed.get("timestamp"))
        cve = feed.get("cve", "unknown")

        # Create base artifact
        artifact = _create_artifact_base(
            container_id=container_id,
            name=f"CVE Artifact: {cve}",
            container_label=container_label,
            severity=None,  # CVEs don't have severity in this context
            tags=[GREYNOISE_FEED_TAG, GREYNOISE_FEED_CVE_TAG],
        )

        # Process state data safely
        old_state = feed.get("old_state", {}) or {}
        new_state = feed.get("new_state", {}) or {}

        # Add CVE-specific CEF fields
        artifact["cef"] = {
            "cve": cve,
            "oldState": convert_activity_state(old_state),
            "newState": convert_activity_state(new_state),
            "timestamp": formatted_timestamp,
            "oldCveStats": convert_to_cef_fields({k: v for k, v in old_state.items() if k != "activity_seen"}),
            "newCveStats": convert_to_cef_fields({k: v for k, v in new_state.items() if k != "activity_seen"}),
        }

        artifact["cef_types"] = {
            "cve": ["cve"],
        }

        logger.info(f"Creating artifact for GreyNoise feed for CVE: {cve}")
        response = soar_rest_client.session.post(
            f"{soar_rest_client.base_url}/artifact",
            json=artifact,
            verify=get_verify_ssl_setting(),
        )
        response.raise_for_status()
        artifact_id = response.json().get("id")
        logger.info(f"Artifact created for GreyNoise feed for CVE: {cve}, ID: {artifact_id}")
        return artifact_id

    except Exception as e:
        logger.error(f"Failed to create CVE feed artifact: {e}")
        raise


def process_feed(feed: dict[str, Any], soar_rest_client: Any, container_label: str) -> tuple[int, int]:
    """
    Process a single feed from the webhook data.

    Args:
        feed: The feed data to process
        soar_rest_client: Client for interacting with SOAR platform
        container_label: The label of the container

    Returns:
        Tuple containing (container_id, artifact_id)

    Raises:
        Exception: If there's an error creating containers or artifacts
    """
    try:
        # Extract critical fields
        feed_event_type = feed.get("event_type")
        feed_timestamp = feed.get("timestamp")

        container_id = create_feed_container(feed_timestamp, soar_rest_client, container_label)

        if feed_event_type == GREYNOISE_FEED_IP_EVENT_TYPE:
            artifact_id = create_feed_ip_artifact(container_id, feed, soar_rest_client, container_label)
        elif feed_event_type == GREYNOISE_FEED_CVE_EVENT_TYPE:
            artifact_id = create_feed_cve_artifact(container_id, feed, soar_rest_client, container_label)
        else:
            logger.warning(f"Unknown feed event type: {feed_event_type}")
            artifact_id = 0  # No artifact created

        return container_id, artifact_id
    except Exception as e:
        logger.error(f"Error processing feed: {e}")
        raise


def handle_webhook(
    method: str,
    headers: dict[str, str],
    path_parts: list[str],
    query: dict[str, Union[str, list[str]]],
    body: str,
    asset: dict[str, Any],
    soar_rest_client: Any,
) -> dict[str, Any]:
    """
    Handle incoming webhooks from GreyNoise.

    This function processes incoming data from GreyNoise's webhook integration,
    creates containers and artifacts based on the data, and returns an appropriate response.

    Args:
        method: HTTP method used in the request (e.g., 'POST', 'GET')
        headers: HTTP headers from the request
        path_parts: Components of the URL path
        query: URL query parameters
        body: Request body as a string
        asset: Asset configuration information
        soar_rest_client: Client for interacting with SOAR platform

    Returns:
        A dictionary with the response status code and content
    """
    # Take container label from asset configuration
    container_label = asset.get("ingest", {}).get("container_label", "events")
    # Validate request
    validated_data, error_response = validate_request(method, body)
    if error_response:
        return error_response

    if validated_data.get("alert"):
        # If request has alert key, process it as a alert
        logger.info("Received webhook request for alert from GreyNoise")
        container_id, artifact_ids = process_alert(validated_data, soar_rest_client, container_label)

    if validated_data.get("event_type"):
        # If request has event_type key, process it as a event
        logger.info("Received webhook request for feed from GreyNoise")
        container_id, artifact_ids = process_feed(validated_data, soar_rest_client, container_label)

    # Return success response with all created IDs
    return create_success_response(container_id, artifact_ids)
