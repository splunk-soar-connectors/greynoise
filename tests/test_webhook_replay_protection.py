# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import hashlib
import hmac
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock


def _load_webhook_module():
    phantom_common = types.ModuleType("phantom_common")
    install_info = types.ModuleType("phantom_common.install_info")
    install_info.get_verify_ssl_setting = lambda: False
    sys.modules.setdefault("phantom_common", phantom_common)
    sys.modules.setdefault("phantom_common.install_info", install_info)

    module_path = Path(__file__).parents[1] / "greynoise_webhook.py"
    spec = importlib.util.spec_from_file_location("greynoise_webhook", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WebhookReplayProtectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.webhook = _load_webhook_module()

    def test_authenticated_body_has_stable_asset_scoped_delivery_identifier(self):
        body = json.dumps({"timestamp": "2026-08-05T20:00:00Z", "alert": {"name": "test"}})
        secret = "test-secret"  # pragma: allowlist secret
        signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        captured_identifiers = []

        def process_alert(_data, _client, _label, delivery_sdi):
            captured_identifiers.append(delivery_sdi)
            return 7, [11]

        original = self.webhook.process_alert
        self.webhook.process_alert = process_alert
        try:
            for asset_id, path_suffix in ((42, "one"), (42, "two"), (43, "one")):
                client = Mock(asset_id=asset_id)
                response = self.webhook.handle_webhook(
                    "POST",
                    {"X-GreyNoise-Signature": signature},
                    [path_suffix],
                    {},
                    body,
                    {"configuration": {"webhook_secret": secret}},
                    client,
                )
                self.assertEqual(response["status_code"], 200)
        finally:
            self.webhook.process_alert = original

        self.assertEqual(captured_identifiers[0], captured_identifiers[1])
        self.assertNotEqual(captured_identifiers[0], captured_identifiers[2])

    def test_delivery_identifier_is_written_to_container_and_artifact_payloads(self):
        response = Mock()
        response.json.return_value = {"id": 17}
        session = Mock()
        session.post.return_value = response
        client = Mock(base_url="https://soar.example", session=session)

        self.webhook.create_alert_container(
            {"name": "test", "type": "ip"},
            "2026-08-05T20:00:00Z",
            client,
            "events",
            "delivery-identifier",
        )
        container_payload = session.post.call_args.kwargs["json"]
        self.assertEqual(container_payload["source_data_identifier"], "delivery-identifier")

        artifact = self.webhook._create_artifact_base(17, "test", "events", "high", ["greynoise"], "delivery-identifier")
        self.assertEqual(artifact["source_data_identifier"], "delivery-identifier")

    def test_platform_duplicate_response_returns_existing_record(self):
        response = Mock()
        response.json.return_value = {"existing_artifact_id": 23}

        self.assertEqual(self.webhook._created_or_existing_id(response, "existing_artifact_id"), 23)
        response.raise_for_status.assert_not_called()

    def test_feed_container_lookup_uses_asset_scoped_identifier(self):
        response = Mock()
        response.json.return_value = {"count": 1, "data": [{"id": 31}]}
        session = Mock()
        session.get.return_value = response
        client = Mock(base_url="https://soar.example", session=session)

        container_id = self.webhook.create_feed_container(
            "2026-08-05T20:00:00Z",
            client,
            "events",
            "asset-scoped-feed-identifier",
        )

        self.assertEqual(container_id, 31)
        self.assertEqual(
            session.get.call_args.kwargs["params"],
            {
                "_filter_source_data_identifier": '"asset-scoped-feed-identifier"',
                "_filter_label": '"events"',
            },
        )


if __name__ == "__main__":
    unittest.main()
