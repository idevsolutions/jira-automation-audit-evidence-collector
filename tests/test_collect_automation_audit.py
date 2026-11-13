# Copyright 2026 iDev Solutions
# SPDX-License-Identifier: Apache-2.0

import csv
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo


SCRIPT = Path(__file__).resolve().parents[1] / "collect_automation_audit.py"
SPEC = importlib.util.spec_from_file_location("collect_automation_audit", SCRIPT)
collector = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(collector)


RULE_ID = "11111111-1111-4111-8111-111111111111"


class CollectorTests(unittest.TestCase):
    def test_public_version_is_explicit(self):
        self.assertEqual(collector.COLLECTOR_VERSION, "0.2.0")

    def test_names_and_verifies_reusable_detail_parts(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "automation-audit-details-full.json"
            part = collector.detail_part_path(output, 2, 32)
            self.assertEqual(part.name, "automation-audit-details-full-part-0002-of-0032.json")
            collector.write_json_atomic(part, {
                "schemaVersion": "automation-audit-detail/0.2",
                "coverage": {"collectionId": "a" * 64, "partNumber": 2, "totalParts": 32},
                "executions": [{"auditLogId": "audit-2"}],
            })
            self.assertTrue(collector.reusable_detail_part(
                part, "a" * 64, 2, 32, ["audit-2"],
            ))
            self.assertFalse(collector.reusable_detail_part(
                part, "a" * 64, 2, 32, ["different"],
            ))

    def test_promotes_a_compatible_bounded_sample_to_the_first_full_collection_part(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "automation-audit-details-sample.json"
            target = Path(directory) / "automation-audit-details-sample-part-0001-of-0002.json"
            collector.write_json_atomic(source, {
                "schemaVersion": "automation-audit-detail/0.2",
                "coverage": {"truncatedByMaxRecords": True},
                "rules": [{"ruleIdUuid": RULE_ID}],
                "executions": [{"auditLogId": "audit-1"}],
            })

            promoted = collector.promote_legacy_detail_seed(
                source, target, "b" * 64, 2, 2, ["audit-1"], 10, 3, 1, False,
            )

            self.assertTrue(promoted)
            payload = collector.json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(payload["coverage"]["collectionId"], "b" * 64)
            self.assertEqual(payload["coverage"]["partNumber"], 1)
            self.assertFalse(payload["coverage"]["truncatedByMaxRecords"])

    def test_retries_a_transient_network_timeout(self):
        class Response:
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b'{"items": []}'

        with (
            patch.object(collector.urllib.request, "urlopen", side_effect=[TimeoutError(), Response()]) as urlopen,
            patch.object(collector.time, "sleep") as sleep,
        ):
            result = collector.post_json("https://example.invalid", {}, "Basic synthetic", retries=1)

        self.assertEqual(result, {"items": []})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_normalizes_record_without_retaining_associated_item_values(self):
        row = collector.normalize_record({
            "auditLogId": "audit-1",
            "ruleUuid": RULE_ID,
            "ruleName": "Synthetic rule",
            "status": "NO_ACTIONS_PERFORMED",
            "startTime": "2026-10-24T15:00:00Z",
            "endTime": "2026-10-24T15:00:01.250Z",
            "associatedItems": [{"id": "PRIVATE-1"}, {"id": "PRIVATE-2"}],
        }, ZoneInfo("America/Sao_Paulo"))

        self.assertEqual(row, {
            "Start time": "10/24/26, 12:00 PM",
            "Audit log ID": "audit-1",
            "Rule": "Synthetic rule",
            "Rule ID": RULE_ID,
            "Status": "NO_ACTIONS_PERFORMED",
            "Total time": "1250ms",
            "Associated items": "item-1,item-2",
            "End time": "10/24/26, 12:00 PM",
        })
        self.assertNotIn("PRIVATE", str(row))

    def test_supports_nested_uuid_epoch_time_and_derived_end(self):
        row = collector.normalize_record({
            "id": 42,
            "rule": {"uuid": RULE_ID, "name": "Nested rule"},
            "executionStatus": "success",
            "created": 1792854000000,
            "durationMs": 500,
            "associatedItems": 3,
        }, ZoneInfo("UTC"))

        self.assertEqual(row["Audit log ID"], "42")
        self.assertEqual(row["Rule ID"], RULE_ID)
        self.assertEqual(row["Status"], "SUCCESS")
        self.assertEqual(row["Total time"], "500ms")
        self.assertEqual(row["Associated items"], "item-1,item-2,item-3")

    def test_preserves_only_safe_atlassian_step_usage_fields(self):
        row = collector.normalize_record({
            "id": "audit-steps",
            "ruleIdUuid": RULE_ID,
            "category": "SUCCESS",
            "startTime": "2026-10-24T15:00:00Z",
            "endTime": "2026-10-24T15:00:01Z",
            "automationStepUsage": {
                "totalSteps": 17,
                "status": "complete",
                "privateValue": "DO_NOT_WRITE",
            },
        }, ZoneInfo("UTC"))

        self.assertEqual(row["Automation steps"], "17")
        self.assertEqual(row["Step usage status"], "COMPLETE")
        self.assertNotIn("DO_NOT_WRITE", str(row))

    def test_names_overview_parts_and_validates_rule_filter_uuid(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "automation-audit-logs-cycle.csv"
            self.assertEqual(
                collector.csv_part_path(output, 2, 14).name,
                "automation-audit-logs-cycle-part-0002-of-0014.csv",
            )
        self.assertEqual(collector.safe_rule_uuid(RULE_ID.upper()), RULE_ID)
        with self.assertRaisesRegex(collector.argparse.ArgumentTypeError, "UUID"):
            collector.safe_rule_uuid("rule name")
        targets = collector.detail_listing_targets("https://example/rest/GLOBAL", [RULE_ID])
        self.assertEqual(targets, [(
            RULE_ID,
            f"https://example/rest/GLOBAL/rule/{RULE_ID}/auditlog",
        )])

    def test_fails_closed_without_rule_uuid(self):
        with self.assertRaisesRegex(collector.MappingError, "rule UUID"):
            collector.normalize_record({
                "id": "audit-1",
                "ruleId": 123,
                "status": "SUCCESS",
                "created": "2026-10-24T15:00:00Z",
                "durationMs": 10,
            }, ZoneInfo("UTC"))

    def test_writes_only_the_analyzer_header_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "automation-audit-logs-test.csv"
            row = {header: "" for header in collector.ANALYZER_HEADERS}
            collector.write_csv_atomic(output, [row])
            with output.open(encoding="utf-8-sig", newline="") as handle:
                reader = csv.reader(handle)
                self.assertEqual(tuple(next(reader)), collector.ANALYZER_HEADERS)

    def test_validates_the_native_export_contract(self):
        source = (",".join(collector.ANALYZER_HEADERS) + "\n").encode()
        self.assertEqual(
            collector.validate_native_export(source, "text/csv"),
            source.decode(),
        )
        with self.assertRaisesRegex(RuntimeError, "Headers received"):
            collector.validate_native_export(b"id,status\n", "text/csv")

    def test_normalizes_native_export_times_to_utc(self):
        self.assertEqual(
            collector.iso_utc("2026-10-01T00:00:00-03:00"),
            "2026-10-01T03:00:00.000Z",
        )

    def test_finds_records_in_the_post_listing_response(self):
        records = [{"auditLogId": "a-1"}]
        self.assertIs(collector.find_records({"data": {"auditItems": records}})[0], records[0])

    def test_maps_the_observed_internal_listing_contract(self):
        record = {
            "associatedIds": ["ISSUE_PRIVATE_1", "ISSUE_PRIVATE_2"],
            "category": "SUCCESS",
            "durationMs": 68050,
            "endTime": 1792533656070,
            "id": 14784591210,
            "ruleId": 2453424,
            "ruleIdUuid": RULE_ID,
            "ruleName": "Observed rule",
            "startTime": 1792533643173,
        }
        payload = {
            "items": {
                "rulesInProgress": {
                    "limit": 50,
                    "offset": 0,
                    "total": 0,
                    "results": [],
                },
                "items": [record],
                "total": 0,
            },
            "executionsWithSuspendedItems": [],
        }

        records = collector.find_records(payload)
        self.assertIs(records[0], record)
        row = collector.normalize_record(records[0], ZoneInfo("America/Sao_Paulo"))
        self.assertEqual(row["Audit log ID"], "14784591210")
        self.assertEqual(row["Rule ID"], RULE_ID)
        self.assertEqual(row["Status"], "SUCCESS")
        self.assertEqual(row["Associated items"], "item-1,item-2")
        self.assertNotIn("PRIVATE", str(row))

    def test_identifies_config_change_as_administrative_not_execution(self):
        record = {
            "id": 14784591211,
            "ruleIdUuid": RULE_ID,
            "category": "CONFIG_CHANGE",
            "automationStepUsage": {"status": "NOT_APPLICABLE", "totalSteps": 0},
            "startTime": 1792533643173,
            "endTime": 1792533643173,
        }

        self.assertTrue(collector.is_non_execution_record(record))
        with self.assertRaisesRegex(collector.MappingError, "CONFIG_CHANGE"):
            collector.normalize_record(record, ZoneInfo("UTC"))

    def test_unknown_execution_category_still_fails_closed(self):
        record = {
            "id": 14784591212,
            "ruleIdUuid": RULE_ID,
            "category": "NEW_EXECUTION_OUTCOME",
            "startTime": 1792533643173,
            "endTime": 1792533643173,
        }

        self.assertFalse(collector.is_non_execution_record(record))
        with self.assertRaisesRegex(collector.MappingError, "NEW_EXECUTION_OUTCOME"):
            collector.normalize_record(record, ZoneInfo("UTC"))

    def test_identifies_in_progress_execution_without_treating_it_as_completed(self):
        record = {
            "id": 14784591213,
            "executionUuid": "22222222-2222-4222-8222-222222222222",
            "ruleIdUuid": RULE_ID,
            "category": "IN_PROGRESS",
            "automationStepUsage": {"status": "IN_PROGRESS", "totalSteps": 2},
            "startTime": 1792533643173,
            "endTime": 1792533643173,
        }

        self.assertTrue(collector.is_in_progress_record(record))
        self.assertFalse(collector.is_non_execution_record(record))
        with self.assertRaisesRegex(collector.MappingError, "IN_PROGRESS"):
            collector.normalize_record(record, ZoneInfo("UTC"))

    def test_sanitizes_detailed_execution_without_item_values(self):
        detail = {
            "id": 14784591210,
            "ruleIdUuid": RULE_ID,
            "category": "SOME_ERRORS",
            "startTime": 1792533643173,
            "endTime": 1792533656070,
            "durationMs": 12897,
            "associatedIds": ["ISSUE_PRIVATE_1"],
            "content": {
                "componentLogs": [{
                    "component": {
                        "id": "component-1",
                        "type": "jira.condition.if.block",
                        "parentId": "component-parent",
                        "componentType": "CONDITION_BLOCK",
                    },
                    "nameKey": "condition.name",
                    "associatedItems": [{"id": "PRIVATE", "payload": {"url": "https://private"}}],
                    "changes": [{
                        "childComponent": {
                            "id": "condition-1",
                            "type": "jira.issue.condition",
                            "parentId": "component-1",
                            "componentType": "CONDITION",
                        },
                        "payload": {
                            "type": "INFO",
                            "key": "condition.failed",
                            "appendParameters": ["ISSUE_PRIVATE_1"],
                        },
                    }],
                    "executionResult": {"continuation": "CONTINUE_RULE"},
                }],
            },
        }

        result = collector.sanitize_execution(
            detail, "14784591210", RULE_ID, reported_steps=0,
            step_usage_status="AVAILABLE",
        )

        self.assertEqual(result["associatedItemCount"], 1)
        self.assertEqual(result["reportedSteps"], 0)
        self.assertEqual(result["stepUsageStatus"], "AVAILABLE")
        self.assertEqual(result["componentLogs"][0]["associatedItemCount"], 1)
        self.assertEqual(result["componentLogs"][0]["changes"][0]["payload"]["parameterCount"], 1)
        self.assertNotIn("PRIVATE", str(result))
        self.assertNotIn("https://", str(result))

    def test_sanitizes_rule_to_topology_without_component_values(self):
        rule = {
            "idUuid": RULE_ID,
            "state": "ENABLED",
            "billingType": "NORMAL",
            "canOtherRuleTrigger": True,
            "ruleScope": {"resources": ["ari:cloud:jira:PRIVATE:project/10000"]},
            "trigger": {
                "id": "trigger-1",
                "component": "TRIGGER",
                "type": "jira.issue.event.trigger:created",
                "value": {"secret": "PRIVATE"},
                "conditions": [{
                    "id": "condition-1",
                    "conditionParentId": "trigger-1",
                    "component": "CONDITION",
                    "type": "jira.issue.condition",
                    "value": {"query": "PRIVATE"},
                }],
            },
            "components": [],
        }

        result = collector.sanitize_rule(rule, RULE_ID)

        self.assertEqual(result["scope"], {"resourceCount": 1, "kinds": ["PROJECT"]})
        self.assertEqual(result["trigger"]["conditions"][0]["type"], "jira.issue.condition")
        self.assertNotIn("value", str(result))
        self.assertNotIn("PRIVATE", str(result))


if __name__ == "__main__":
    unittest.main()
