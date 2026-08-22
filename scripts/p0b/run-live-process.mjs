#!/usr/bin/env node

import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "../../apps/web-console/node_modules/@playwright/test/index.mjs";
import { collectFixtureProvenance, startFixture, stopFixture } from "./postgres-tls/fixture.mjs";
import { runQualificationCommand } from "./qualification/command.mjs";
import {
  buildP0BQualificationReport,
  digestArtifactTree,
  resolveSourceTree,
  resolveSourceState,
  writeP0BQualificationReport
} from "./qualification/report.mjs";
import { collectBrowserMetadata, evidenceDigest } from "./qualification/runtime-evidence.mjs";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, "../..");
const CONSOLE_ROOT = path.join(REPOSITORY_ROOT, "apps/web-console");
const LIVE_TEST = path.join(REPOSITORY_ROOT, "test/p0b-live-process.integration.test.mjs");
const LIVE_BROWSER_TEST = path.join(REPOSITORY_ROOT, "test/p0b-live-browser.integration.test.mjs");
const DEFAULT_FIXTURE_TIMEOUT_MS = 45_000;
const MAX_ENV_FILE_BYTES = 16 * 1024;
const DEFAULT_REPORT_OUTPUT = path.join(REPOSITORY_ROOT, ".agentpass", "qualification", "p0b.json");
const BUILD_TIMEOUT_MS = 180_000;
// The live browser matrix intentionally provisions an isolated PostgreSQL,
// Cloud, and Console stack per authority scenario. Keep the outer supervisor
// above the complete matrix budget; each scenario retains its own tighter
// deadline so a single stuck interaction still fails locally.
const BROWSER_TIMEOUT_MS = 1_920_000;
const PROCESS_TIMEOUT_MS = 180_000;
// Only these static TAP fragments may cross the child-output boundary. The
// command runner retains the fixed code, never the matched line or adjacent
// diagnostics, so assertions, URLs, credentials, SQL, and tenant data remain
// unavailable to the orchestrator and CI log.
const LIVE_BROWSER_SAFE_FAILURE_MARKERS = Object.freeze([
  [null, "P0B_SAFE_WAKE_COALESCED_FAILED", "wake_ledger_coalesced"],
  [null, "P0B_SAFE_WAKE_NO_PENDING_FAILED", "wake_ledger_no_pending"],
  [null, "P0B_SAFE_WAKE_ACCEPTED_FAILED", "wake_ledger_accepted"],
  [null, "P0B_SAFE_WAKE_ACCEPTED_GOT_COALESCED_FAILED", "wake_ledger_accepted_got_coalesced"],
  [null, "P0B_SAFE_WAKE_ACCEPTED_GOT_NO_PENDING_FAILED", "wake_ledger_accepted_got_no_pending"],
  [null, "P0B_SAFE_WAKE_ACCEPTED_STATUS_MISMATCH_FAILED", "wake_ledger_accepted_status_mismatch"],
  [null, "P0B_SAFE_WAKE_ACCEPTED_UI_STATUS_FAILED", "wake_ledger_accepted_ui_status"],
  [null, "P0B_SAFE_KEYBOARD_FOCUS_FAILED", "keyboard_focus"],
  [null, "P0B_SAFE_KEYBOARD_PRESS_FAILED", "keyboard_press"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_FAILED", "keyboard_outcome"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_ALERT_FAILED", "keyboard_outcome_alert"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_TIMEOUT_FAILED", "keyboard_outcome_timeout"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_INVALID_FAILED", "keyboard_outcome_invalid"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_TRANSPORT_FAILED", "keyboard_outcome_transport"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_NO_REQUEST_FAILED", "keyboard_outcome_no_request"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_RESPONSE_TIMEOUT_FAILED", "keyboard_outcome_response_timeout"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_400_FAILED", "keyboard_outcome_http_400"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_401_FAILED", "keyboard_outcome_http_401"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_403_FAILED", "keyboard_outcome_http_403"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_409_FAILED", "keyboard_outcome_http_409"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_422_FAILED", "keyboard_outcome_http_422"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_429_FAILED", "keyboard_outcome_http_429"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_500_FAILED", "keyboard_outcome_http_500"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_502_FAILED", "keyboard_outcome_http_502"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_503_FAILED", "keyboard_outcome_http_503"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_504_FAILED", "keyboard_outcome_http_504"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_4XX_FAILED", "keyboard_outcome_http_4xx"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_5XX_FAILED", "keyboard_outcome_http_5xx"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_OTHER_FAILED", "keyboard_outcome_http_other"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_2XX_RESPONSE_CONTRACT_FAILED", "keyboard_outcome_2xx_response_contract"],
  [null, "P0B_SAFE_KEYBOARD_OUTCOME_2XX_UI_PARSE_FAILED", "keyboard_outcome_2xx_ui_parse"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_NO_REQUEST_FAILED", "keyboard_auth_options_no_request"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_WEBAUTHN_UNAVAILABLE_FAILED", "keyboard_auth_webauthn_unavailable"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_SESSION_TRANSPORT_FAILED", "keyboard_auth_session_transport"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_SESSION_RESPONSE_MISSING_FAILED", "keyboard_auth_session_response_missing"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_SESSION_HTTP_4XX_FAILED", "keyboard_auth_session_http_4xx"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_SESSION_HTTP_5XX_FAILED", "keyboard_auth_session_http_5xx"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_SESSION_HTTP_OTHER_FAILED", "keyboard_auth_session_http_other"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_SESSION_SUCCEEDED_NO_OPTIONS_FAILED", "keyboard_auth_session_succeeded_no_options"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_TRANSPORT_FAILED", "keyboard_auth_options_transport"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_RESPONSE_MISSING_FAILED", "keyboard_auth_options_response_missing"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_HTTP_4XX_FAILED", "keyboard_auth_options_http_4xx"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_HTTP_5XX_FAILED", "keyboard_auth_options_http_5xx"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_HTTP_OTHER_FAILED", "keyboard_auth_options_http_other"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_NO_REQUEST_FAILED", "keyboard_auth_verify_no_request"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_TRANSPORT_FAILED", "keyboard_auth_verify_transport"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_RESPONSE_MISSING_FAILED", "keyboard_auth_verify_response_missing"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_400_FAILED", "keyboard_auth_verify_http_400"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_401_FAILED", "keyboard_auth_verify_http_401"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_401_CREDENTIAL_NOT_ALLOWED_FAILED", "keyboard_auth_verify_credential_not_allowed"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_401_WEBAUTHN_VERIFICATION_FAILED_FAILED", "keyboard_auth_verify_webauthn_verification_failed"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_401_SESSION_REQUIRED_FAILED", "keyboard_auth_verify_session_required"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_403_FAILED", "keyboard_auth_verify_http_403"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_409_FAILED", "keyboard_auth_verify_http_409"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_422_FAILED", "keyboard_auth_verify_http_422"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_428_FAILED", "keyboard_auth_verify_http_428"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_429_FAILED", "keyboard_auth_verify_http_429"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_4XX_FAILED", "keyboard_auth_verify_http_4xx"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_5XX_FAILED", "keyboard_auth_verify_http_5xx"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_OTHER_FAILED", "keyboard_auth_verify_http_other"],
  [null, "P0B_SAFE_KEYBOARD_AUTH_VERIFIED_NO_REFRESH_FAILED", "keyboard_auth_verified_no_refresh"],
  [null, "P0B_SAFE_SCENARIO_NOT_FOUND", "scenario_not_found"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_01_FAILED", "scenario_unclassified_01"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_02_FAILED", "scenario_unclassified_02"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_03_FAILED", "scenario_unclassified_03"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_04_FAILED", "scenario_unclassified_04"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_05_FAILED", "scenario_unclassified_05"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_06_FAILED", "scenario_unclassified_06"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_07_FAILED", "scenario_unclassified_07"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_08_FAILED", "scenario_unclassified_08"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_09_FAILED", "scenario_unclassified_09"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_10_FAILED", "scenario_unclassified_10"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_11_FAILED", "scenario_unclassified_11"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_12_FAILED", "scenario_unclassified_12"],
  [null, "P0B_SAFE_SCENARIO_UNCLASSIFIED_13_FAILED", "scenario_unclassified_13"],
  [null, "P0B_SAFE_STATE_MISSING_SYNCED", "state_missing_synced"],
  [null, "P0B_SAFE_STATE_MISSING_PENDING", "state_missing_pending"],
  [null, "P0B_SAFE_STATE_MISSING_BLOCKED", "state_missing_blocked"],
  [null, "P0B_SAFE_STATE_MISSING_STALE", "state_missing_stale"],
  [null, "P0B_SAFE_STATE_MISSING_OFFLINE", "state_missing_offline"],
  [null, "P0B_SAFE_STATE_MISSING_REVOKED", "state_missing_revoked"],
  [null, "P0B_SAFE_OWNER_OPEN_CONTEXT_FAILED", "owner_open_context"],
  [null, "P0B_SAFE_OWNER_OPEN_AUTHENTICATOR_FAILED", "owner_open_authenticator"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_FAILED", "owner_open_bootstrap"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_FAILED", "owner_open_registration"],
  [null, "P0B_SAFE_OWNER_OPEN_RELOAD_FAILED", "owner_open_reload"],
  [null, "P0B_SAFE_OWNER_OPEN_READINESS_FAILED", "owner_open_readiness"],
  [null, "P0B_SAFE_OWNER_OPEN_SUMMARY_NO_RESPONSE_FAILED", "owner_open_summary_no_response"],
  [null, "P0B_SAFE_OWNER_OPEN_SUMMARY_NO_REQUEST_FAILED", "owner_open_summary_no_request"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_NO_RESPONSE_FAILED", "owner_open_session_no_response"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_HTTP_401_FAILED", "owner_open_session_http_401"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_HTTP_403_FAILED", "owner_open_session_http_403"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_HTTP_5XX_FAILED", "owner_open_session_http_5xx"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_RESPONSE_CONTRACT_FAILED", "owner_open_session_response_contract"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_INVALID_JSON_FAILED", "owner_open_session_invalid_json"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_RESPONSE_CONTRACT_PAYLOAD_SHAPE_FAILED", "owner_open_session_contract_payload_shape"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_RESPONSE_CONTRACT_TOP_KEYS_FAILED", "owner_open_session_contract_top_keys"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_RESPONSE_CONTRACT_SESSION_SHAPE_FAILED", "owner_open_session_contract_session_shape"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_RESPONSE_CONTRACT_SESSION_KEYS_FAILED", "owner_open_session_contract_session_keys"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_RESPONSE_CONTRACT_FIELD_TYPES_FAILED", "owner_open_session_contract_field_types"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_RESPONSE_CONTRACT_CSRF_TYPE_FAILED", "owner_open_session_contract_csrf_type"],
  [null, "P0B_SAFE_OWNER_OPEN_SESSION_RESPONSE_CONTRACT_VALID_SHAPE_FAILED", "owner_open_session_contract_valid_shape"],
  [null, "P0B_SAFE_OWNER_OPEN_SUMMARY_HTTP_401_FAILED", "owner_open_summary_http_401"],
  [null, "P0B_SAFE_OWNER_OPEN_SUMMARY_HTTP_403_FAILED", "owner_open_summary_http_403"],
  [null, "P0B_SAFE_OWNER_OPEN_SUMMARY_HTTP_500_FAILED", "owner_open_summary_http_500"],
  [null, "P0B_SAFE_OWNER_OPEN_SUMMARY_HTTP_4XX_FAILED", "owner_open_summary_http_4xx"],
  [null, "P0B_SAFE_OWNER_OPEN_SUMMARY_HTTP_5XX_FAILED", "owner_open_summary_http_5xx"],
  [null, "P0B_SAFE_OWNER_OPEN_SUMMARY_RESPONSE_CONTRACT_FAILED", "owner_open_summary_response_contract"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_NAVIGATION_FAILED", "owner_open_bootstrap_navigation"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_RESPONSE_FAILED", "owner_open_bootstrap_response"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_400_FAILED", "owner_open_bootstrap_http_400"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_401_FAILED", "owner_open_bootstrap_http_401"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_403_FAILED", "owner_open_bootstrap_http_403"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_404_FAILED", "owner_open_bootstrap_http_404"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_405_FAILED", "owner_open_bootstrap_http_405"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_409_FAILED", "owner_open_bootstrap_http_409"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_415_FAILED", "owner_open_bootstrap_http_415"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_422_FAILED", "owner_open_bootstrap_http_422"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_429_FAILED", "owner_open_bootstrap_http_429"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_500_FAILED", "owner_open_bootstrap_http_500"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_502_BFF_INVALID_RESPONSE_FAILED", "owner_open_bootstrap_http_502_bff_invalid_response"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_502_PROXY_UNAVAILABLE_FAILED", "owner_open_bootstrap_http_502_proxy_unavailable"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_502_CLOUD_EXITED_FAILED", "owner_open_bootstrap_http_502_cloud_exited"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_504_FAILED", "owner_open_bootstrap_http_504"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_4XX_FAILED", "owner_open_bootstrap_http_4xx"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_5XX_FAILED", "owner_open_bootstrap_http_5xx"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_HTTP_OTHER_FAILED", "owner_open_bootstrap_http_other"],
  [null, "P0B_SAFE_OWNER_OPEN_BOOTSTRAP_CONTRACT_FAILED", "owner_open_bootstrap_contract"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_400_FAILED", "owner_registration_options_400"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_401_FAILED", "owner_registration_options_401"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_403_FAILED", "owner_registration_options_403"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_409_FAILED", "owner_registration_options_409"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_413_FAILED", "owner_registration_options_413"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_422_FAILED", "owner_registration_options_422"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_428_FAILED", "owner_registration_options_428"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_500_FAILED", "owner_registration_options_500"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_503_FAILED", "owner_registration_options_503"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_503_CONTROL_UNAVAILABLE_FAILED", "owner_reg_options_control_unavailable"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_503_SESSION_UNAVAILABLE_FAILED", "owner_reg_options_session_unavailable"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_OPTIONS_503_SERVICE_UNAVAILABLE_FAILED", "owner_reg_options_service_unavailable"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_400_FAILED", "owner_registration_verify_400"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_FAILED", "owner_registration_verify_401"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_REQUIRED_FAILED", "owner_reg_verify_session_required"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_MISSING_FAILED", "owner_reg_session_missing"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_REVOKED_FAILED", "owner_reg_session_revoked"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_REVOKED_EXPIRED_FAILED", "owner_reg_session_revoked_expired"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_REVOKED_CONCURRENT_FAILED", "owner_reg_session_revoked_concurrent"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_REVOKED_ROTATED_FAILED", "owner_reg_session_revoked_rotated"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_REVOKED_LOGOUT_FAILED", "owner_reg_session_revoked_logout"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_REVOKED_OTHER_FAILED", "owner_reg_session_revoked_other"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_ABSOLUTE_EXPIRED_FAILED", "owner_reg_session_absolute_expired"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_IDLE_EXPIRED_FAILED", "owner_reg_session_idle_expired"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_ACTIVE_FAILED", "owner_reg_session_active"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_SESSION_UNAVAILABLE_FAILED", "owner_reg_session_state_unavailable"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_401_COOKIE_MISSING_FAILED", "owner_reg_verify_cookie_missing"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_403_FAILED", "owner_registration_verify_403"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_409_FAILED", "owner_registration_verify_409"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_413_FAILED", "owner_registration_verify_413"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_422_FAILED", "owner_registration_verify_422"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_428_FAILED", "owner_registration_verify_428"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_500_FAILED", "owner_registration_verify_500"],
  [null, "P0B_SAFE_OWNER_OPEN_REGISTRATION_VERIFY_503_FAILED", "owner_registration_verify_503"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_500_FAILED", "admin_open_bootstrap_http_500"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_NAVIGATION_FAILED", "admin_open_bootstrap_navigation"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_RESPONSE_FAILED", "admin_open_bootstrap_response"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_400_FAILED", "admin_open_bootstrap_http_400"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_401_FAILED", "admin_open_bootstrap_http_401"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_403_FAILED", "admin_open_bootstrap_http_403"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_404_FAILED", "admin_open_bootstrap_http_404"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_405_FAILED", "admin_open_bootstrap_http_405"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_409_FAILED", "admin_open_bootstrap_http_409"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_415_FAILED", "admin_open_bootstrap_http_415"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_422_FAILED", "admin_open_bootstrap_http_422"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_429_FAILED", "admin_open_bootstrap_http_429"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_OTHER_FAILED", "admin_open_bootstrap_http_other"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_502_BFF_INVALID_RESPONSE_FAILED", "admin_open_bootstrap_http_502_bff_invalid_response"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_502_PROXY_UNAVAILABLE_FAILED", "admin_open_bootstrap_http_502_proxy_unavailable"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_502_CLOUD_EXITED_FAILED", "admin_open_bootstrap_http_502_cloud_exited"],
  [null, "P0B_SAFE_BOOTSTRAP_HTTP_503_SESSION_UNAVAILABLE_FAILED", "bootstrap_http_503_session_unavailable"],
  [null, "P0B_SAFE_BOOTSTRAP_HTTP_503_HUMAN_AUTH_UNAVAILABLE_FAILED", "bootstrap_http_503_human_auth_unavailable"],
  [null, "P0B_SAFE_BOOTSTRAP_HTTP_503_RATE_LIMITER_UNAVAILABLE_FAILED", "bootstrap_http_503_rate_limiter_unavailable"],
  [null, "P0B_SAFE_BOOTSTRAP_HTTP_503_CLOUD_API_UNAVAILABLE_FAILED", "bootstrap_http_503_cloud_api_unavailable"],
  [null, "P0B_SAFE_BOOTSTRAP_HTTP_503_IDENTITY_UNAVAILABLE_FAILED", "bootstrap_http_503_identity_unavailable"],
  [null, "P0B_SAFE_BOOTSTRAP_HTTP_503_OTHER_FAILED", "bootstrap_http_503_other"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_504_FAILED", "admin_open_bootstrap_http_504"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_4XX_FAILED", "admin_open_bootstrap_http_4xx"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_5XX_FAILED", "admin_open_bootstrap_http_5xx"],
  [null, "P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_CONTRACT_FAILED", "admin_open_bootstrap_contract"],
  [null, "P0B_SAFE_ADMIN_OPEN_REGISTRATION_FAILED", "admin_open_registration"],
  [null, "P0B_SAFE_ADMIN_OPEN_RELOAD_FAILED", "admin_open_reload"],
  [null, "P0B_SAFE_ADMIN_OPEN_READINESS_FAILED", "admin_open_readiness"],
  [null, "P0B_SAFE_ADMIN_WAKE_CLICK_FAILED", "admin_wake_click"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_TRANSPORT_FAILED", "admin_wake_auth_options_transport"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_HTTP_4XX_FAILED", "admin_wake_auth_options_http_4xx"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_HTTP_5XX_FAILED", "admin_wake_auth_options_http_5xx"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_HTTP_OTHER_FAILED", "admin_wake_auth_options_http_other"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_TRANSPORT_FAILED", "admin_wake_auth_verify_transport"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_400_FAILED", "admin_wake_auth_verify_http_400"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_401_FAILED", "admin_wake_auth_verify_http_401"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_401_CREDENTIAL_NOT_ALLOWED_FAILED", "admin_wake_auth_verify_credential_not_allowed"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_401_WEBAUTHN_VERIFICATION_FAILED_FAILED", "admin_wake_auth_verify_webauthn_verification_failed"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_401_SESSION_REQUIRED_FAILED", "admin_wake_auth_verify_session_required"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_403_FAILED", "admin_wake_auth_verify_http_403"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_409_FAILED", "admin_wake_auth_verify_http_409"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_422_FAILED", "admin_wake_auth_verify_http_422"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_428_FAILED", "admin_wake_auth_verify_http_428"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_429_FAILED", "admin_wake_auth_verify_http_429"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_4XX_FAILED", "admin_wake_auth_verify_http_4xx"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_5XX_FAILED", "admin_wake_auth_verify_http_5xx"],
  [null, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_OTHER_FAILED", "admin_wake_auth_verify_http_other"],
  [null, "P0B_SAFE_ADMIN_WAKE_REFRESH_TRANSPORT_FAILED", "admin_wake_refresh_transport"],
  [null, "P0B_SAFE_ADMIN_WAKE_REFRESH_RESPONSE_TIMEOUT_FAILED", "admin_wake_refresh_response_timeout"],
  [null, "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_4XX_FAILED", "admin_wake_refresh_http_4xx"],
  [null, "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_5XX_FAILED", "admin_wake_refresh_http_5xx"],
  [null, "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_OTHER_FAILED", "admin_wake_refresh_http_other"],
  [null, "P0B_SAFE_ADMIN_WAKE_REFRESH_2XX_RESPONSE_CONTRACT_FAILED", "admin_wake_refresh_2xx_response_contract"],
  [null, "P0B_SAFE_ADMIN_WAKE_UI_ALERT_FAILED", "admin_wake_ui_alert"],
  [null, "P0B_SAFE_ADMIN_WAKE_UI_TIMEOUT_FAILED", "admin_wake_ui_timeout"],
  [null, "P0B_SAFE_ADMIN_WAKE_UI_COPY_MISMATCH_FAILED", "admin_wake_ui_copy_mismatch"],
  [null, "P0B_SAFE_LIFECYCLE_FIXTURE_STARTUP_TIMEOUT_FAILED", "lifecycle_fixture_startup_timeout"],
  [null, "P0B_SAFE_LIFECYCLE_FIXTURE_START_FAILED", "lifecycle_fixture_start"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_PREPARE_FAILED", "lifecycle_database_prepare"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_RELATION_FAILED", "lifecycle_database_schema_relation"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_COLUMN_FAILED", "lifecycle_database_schema_column"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_FUNCTION_FAILED", "lifecycle_database_schema_function"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_TYPE_FAILED", "lifecycle_database_schema_type"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_PERMISSION_FAILED", "lifecycle_database_schema_permission"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_SYNTAX_FAILED", "lifecycle_database_schema_syntax"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_FEATURE_FAILED", "lifecycle_database_schema_feature"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_CONNECTION_FAILED", "lifecycle_database_schema_connection"],
  [null, "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_QUERY_FAILED", "lifecycle_database_schema_query"],
  [null, "P0B_SAFE_LIFECYCLE_EXTERNAL_DEPENDENCY_FAILED", "lifecycle_external_dependency"],
  [null, "P0B_SAFE_LIFECYCLE_BROWSER_STARTUP_TIMEOUT_FAILED", "lifecycle_browser_startup_timeout"],
  [null, "P0B_SAFE_LIFECYCLE_BROWSER_START_FAILED", "lifecycle_browser_start"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_START_FAILED", "lifecycle_cloud_start"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_POSTGRES_START_FAILED", "lifecycle_cloud_postgres_start"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_CONFIG_START_FAILED", "lifecycle_cloud_config_start"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_SIGNER_START_FAILED", "lifecycle_cloud_signer_start"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_PLATFORM_SESSION_START_FAILED", "lifecycle_cloud_platform_session_start"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_DEPENDENCY_START_FAILED", "lifecycle_cloud_dependency_start"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_UNKNOWN_START_FAILED", "lifecycle_cloud_unknown_start"],
  [null, "P0B_SAFE_LIFECYCLE_CONSOLE_START_FAILED", "lifecycle_console_start"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_READINESS_FAILED", "lifecycle_cloud_readiness"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNAVAILABLE_FAILED", "lifecycle_cloud_health_unavailable"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_READINESS_FAILED", "lifecycle_cloud_health_invalid_readiness"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_READINESS_CHECKS_FAILED", "lifecycle_cloud_health_invalid_readiness_checks"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_DATABASE_FAILED", "lifecycle_cloud_health_database"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_SCHEMA_FAILED", "lifecycle_cloud_health_schema"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_POOL_FAILED", "lifecycle_cloud_health_pool"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_DRAIN_FAILED", "lifecycle_cloud_health_drain"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_PLATFORM_SESSION_FAILED", "lifecycle_cloud_health_platform_session"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_PLATFORM_PROMOTION_FAILED", "lifecycle_cloud_health_platform_promotion"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_SIGNER_SET_FAILED", "lifecycle_cloud_health_signer_set"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_CHECK_FAILED", "lifecycle_cloud_health_unknown_check"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_KEY_", "lifecycle_cloud_health_unknown_key"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_CAPABILITY_MAINTENANCE_FAILED", "lifecycle_cloud_health_capability_maintenance"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_READINESS_CODE_", "lifecycle_cloud_readiness_code"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_CAPABILITY_MAINTENANCE_WORKER_FAILED", "lifecycle_cloud_capability_maintenance_worker"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_READINESS_DISAGREE_FAILED", "lifecycle_cloud_health_readiness_disagree"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_METRICS_FAILED", "lifecycle_cloud_health_unknown_metrics"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_AGENT_SESSION_FAILED", "lifecycle_cloud_health_unknown_agent_session"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_MANIFEST_FAILED", "lifecycle_cloud_health_unknown_manifest"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_POSSESSION_FAILED", "lifecycle_cloud_health_unknown_possession"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_REFRESH_FAILED", "lifecycle_cloud_health_unknown_refresh"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_CAPABILITY_FAILED", "lifecycle_cloud_health_unknown_capability"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_CONTROL_BUNDLE_FAILED", "lifecycle_cloud_health_unknown_control_bundle"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_AUDIT_ANCHOR_FAILED", "lifecycle_cloud_health_unknown_audit_anchor"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_PROMOTION_EVIDENCE_FAILED", "lifecycle_cloud_health_unknown_promotion_evidence"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_MANAGED_SIGNERS_FAILED", "lifecycle_cloud_health_unknown_managed_signers"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_OWNER_OUTBOX_FAILED", "lifecycle_cloud_health_unknown_owner_outbox"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_OUTBOX_FAILED", "lifecycle_cloud_health_unknown_outbox"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_PROVIDER_OPERATIONS_FAILED", "lifecycle_cloud_health_unknown_provider_operations"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_DEVICE_AUDIT_FAILED", "lifecycle_cloud_health_unknown_device_audit"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_DEPLOYMENT_IDENTITY_FAILED", "lifecycle_cloud_health_invalid_deployment_identity"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_MANAGED_SIGNERS_FAILED", "lifecycle_cloud_health_invalid_managed_signers"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_INVALID_REPORT_FAILED", "lifecycle_cloud_health_invalid_report"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_SCHEMA_UNAVAILABLE_FAILED", "lifecycle_cloud_schema_unavailable"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_READINESS_DIAGNOSTIC_FAILED", "lifecycle_cloud_readiness_diagnostic"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_SCHEMA_READINESS_FAILED", "lifecycle_cloud_schema_readiness"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_SIGNER_READINESS_FAILED", "lifecycle_cloud_signer_readiness"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_PLATFORM_SESSION_READINESS_FAILED", "lifecycle_cloud_platform_session_readiness"],
  [null, "P0B_SAFE_LIFECYCLE_CONSOLE_READINESS_FAILED", "lifecycle_console_readiness"],
  [null, "P0B_SAFE_LIFECYCLE_CLOUD_KMS_START_FAILED", "lifecycle_cloud_kms_start"],
  [null, "P0B_SAFE_LIFECYCLE_DEPENDENCY_START_FAILED", "lifecycle_dependency_start"],
  [null, "P0B_SAFE_LIFECYCLE_SIGNER_START_FAILED", "lifecycle_signer_start"],
  [null, "P0B_SAFE_LIFECYCLE_FIXTURE_CLEANUP_FAILED", "lifecycle_fixture_cleanup"],
  [null, "P0B_SAFE_LIFECYCLE_FIXTURE_CLEANUP_TIMEOUT_FAILED", "lifecycle_fixture_cleanup_timeout"],
  [null, "P0B_SAFE_LIFECYCLE_CONTEXT_CLEANUP_TIMEOUT_FAILED", "lifecycle_context_cleanup_timeout"],
  [null, "P0B_SAFE_LIFECYCLE_CONTEXT_CLEANUP_FAILED", "lifecycle_context_cleanup"],
  [null, "P0B_SAFE_LIFECYCLE_BROWSER_CLEANUP_TIMEOUT_FAILED", "lifecycle_browser_cleanup_timeout"],
  [null, "P0B_SAFE_LIFECYCLE_BROWSER_CLEANUP_FAILED", "lifecycle_browser_cleanup"],
  [null, "P0B_SAFE_AUDITOR_OPEN_CONTEXT_FAILED", "auditor_open_context"],
  [null, "P0B_SAFE_AUDITOR_OPEN_AUTHENTICATOR_FAILED", "auditor_open_authenticator"],
  [null, "P0B_SAFE_AUDITOR_OPEN_BOOTSTRAP_FAILED", "auditor_open_bootstrap"],
  [null, "P0B_SAFE_AUDITOR_OPEN_REGISTRATION_FAILED", "auditor_open_registration"],
  [null, "P0B_SAFE_AUDITOR_OPEN_RELOAD_FAILED", "auditor_open_reload"],
  [null, "P0B_SAFE_AUDITOR_OPEN_READINESS_FAILED", "auditor_open_readiness"],
  [null, "P0B_SAFE_AUDITOR_WAKE_CONTROL_FAILED", "auditor_wake_control"],
  [null, "P0B_SAFE_VIEWER_OPEN_FAILED", "viewer_open"],
  [null, "P0B_SAFE_VIEWER_WAKE_CONTROL_FAILED", "viewer_wake_control"],
  [null, "P0B_SAFE_STALE_AUTH_TARGET_FAILED", "stale_auth_target"],
  [null, "P0B_SAFE_STALE_AUTH_CEREMONY_FAILED", "stale_auth_ceremony"],
  [null, "P0B_SAFE_STALE_AUTH_CEREMONY_OPTIONS_FAILED", "stale_auth_ceremony_options"],
  [null, "P0B_SAFE_STALE_AUTH_CEREMONY_VERIFY_FAILED", "stale_auth_ceremony_verify"],
  [null, "P0B_SAFE_STALE_AUTH_CEREMONY_RESPONSE_FAILED", "stale_auth_ceremony_response"],
  [null, "P0B_SAFE_STALE_AUTH_INVALIDATION_FAILED", "stale_auth_invalidation"],
  [null, "P0B_SAFE_STALE_AUTH_FETCH_FAILED", "stale_auth_fetch"],
  [null, "P0B_SAFE_STALE_AUTH_RESPONSE_FAILED", "stale_auth_response"],
  [null, "P0B_SAFE_STALE_AUTH_HTTP_2XX_FAILED", "stale_auth_http_2xx"],
  [null, "P0B_SAFE_STALE_AUTH_HTTP_4XX_FAILED", "stale_auth_http_4xx"],
  [null, "P0B_SAFE_STALE_AUTH_HTTP_5XX_FAILED", "stale_auth_http_5xx"],
  [null, "P0B_SAFE_STALE_AUTH_HTTP_OTHER_FAILED", "stale_auth_http_other"],
  [null, "P0B_SAFE_MISSING_AUTHENTICATOR_WAKE_CLICK_FAILED", "missing_authenticator_wake_click", false],
  [null, "P0B_SAFE_MISSING_AUTHENTICATOR_CONFIRM_FAILED", "missing_authenticator_confirm", false],
  [null, "P0B_SAFE_MISSING_AUTHENTICATOR_ALERT_FAILED", "missing_authenticator_alert", false],
  [null, "P0B_SAFE_MISSING_AUTHENTICATOR_MUTATION_FAILED", "missing_authenticator_mutation", false],
  [null, "P0B_SAFE_CHILD_UNCAUGHT_EXCEPTION", "child_uncaught_exception", false],
  [null, "P0B_SAFE_CHILD_UNHANDLED_REJECTION", "child_unhandled_rejection", false],
].map(([index, name, code, terminate = true]) => Object.freeze({
  marker: index === null ? name : `not ok ${index} - ${name}`,
  code,
  terminate
})));
const REQUIRED_ENV_KEYS = Object.freeze([
  "P0B_POSTGRES_ADMIN_URL",
  "AGENTPASS_TEST_POSTGRES_ADMIN_URL",
  "P0B_POSTGRES_CA_FILE",
  "PGSSLROOTCERT",
  "P0B_POSTGRES_TLS_STATE_FILE",
  "P0B_POSTGRES_TLS_IMAGE",
  "P0B_POSTGRES_TLS_CONTAINER_ID"
]);
const LIVE_BROWSER_SCENARIO_MAX_LENGTH = 128;
const LIVE_BROWSER_SCENARIO_PATTERN = /^[^\u0000-\u001f\u007f]{1,128}$/u;
const ENV_KEY = /^[A-Z][A-Z0-9_]*$/u;
const CONTAINER_ID = /^[a-f0-9]{12,64}$/u;

export class OrchestrationError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "OrchestrationError";
    this.code = code;
  }
}

export function parseArgs(argv) {
  const options = { fixtureTimeoutMs: DEFAULT_FIXTURE_TIMEOUT_MS };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") return Object.freeze({ help: true });
    if (argument === "--fixture-timeout-ms") {
      const value = Number(argv[++index]);
      if (!Number.isSafeInteger(value) || value < 1) {
        throw new OrchestrationError("invalid_argument", "fixture timeout must be a positive integer");
      }
      options.fixtureTimeoutMs = value;
      continue;
    }
    if (argument === "--fixture-image") {
      const value = argv[++index];
      if (typeof value !== "string" || value.length === 0 || value.length > 256) {
        throw new OrchestrationError("invalid_argument", "fixture image is invalid");
      }
      options.fixtureImage = value;
      continue;
    }
    if (argument === "--report-output") {
      const value = argv[++index];
      if (!isSafeAbsolutePath(value)) throw new OrchestrationError("invalid_argument", "report output must be an absolute path");
      options.reportOutput = value;
      continue;
    }
    throw new OrchestrationError("invalid_argument", "unknown option");
  }
  return Object.freeze(options);
}

export async function readProtectedEnvironment(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) {
    throw new OrchestrationError("invalid_env_file", "fixture env file must be absolute");
  }
  let handle;
  try {
    handle = await fsp.open(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const metadata = await handle.stat();
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0 || metadata.size > MAX_ENV_FILE_BYTES) {
      throw new Error("invalid protected env metadata");
    }
    const contents = await handle.readFile("utf8");
    return parseProtectedEnvironment(contents);
  } catch (error) {
    if (error instanceof OrchestrationError) throw error;
    throw new OrchestrationError("invalid_env_file", "fixture env file is unreadable");
  } finally {
    await handle?.close().catch(() => {});
  }
}

export function parseProtectedEnvironment(contents) {
  if (typeof contents !== "string" || contents.length > MAX_ENV_FILE_BYTES || contents.includes("\u0000")) {
    throw new OrchestrationError("invalid_env_file", "fixture env file is invalid");
  }
  const values = Object.create(null);
  const lines = contents.split("\n");
  if (lines.at(-1) === "") lines.pop();
  for (const line of lines) {
    if (line.length === 0 || line.includes("\r")) {
      throw new OrchestrationError("invalid_env_file", "fixture env file is invalid");
    }
    const separator = line.indexOf("=");
    if (separator <= 0) throw new OrchestrationError("invalid_env_file", "fixture env file is invalid");
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (!ENV_KEY.test(key) || Object.hasOwn(values, key) || value.includes("\n") || value.includes("\r")) {
      throw new OrchestrationError("invalid_env_file", "fixture env file is invalid");
    }
    values[key] = value;
  }
  for (const key of REQUIRED_ENV_KEYS) {
    if (typeof values[key] !== "string" || values[key].length === 0) {
      throw new OrchestrationError("invalid_env_file", "fixture env file is incomplete");
    }
  }
  const allowed = new Set(REQUIRED_ENV_KEYS);
  if (Object.keys(values).some((key) => !allowed.has(key))) {
    throw new OrchestrationError("invalid_env_file", "fixture env file contains an unsupported key");
  }
  if (![values.P0B_POSTGRES_CA_FILE, values.PGSSLROOTCERT, values.P0B_POSTGRES_TLS_STATE_FILE]
    .every((value) => path.isAbsolute(value))) {
    throw new OrchestrationError("invalid_env_file", "fixture env paths must be absolute");
  }
  if (!CONTAINER_ID.test(values.P0B_POSTGRES_TLS_CONTAINER_ID)) {
    throw new OrchestrationError("invalid_env_file", "fixture container id is invalid");
  }
  validatePostgresUrl(values.P0B_POSTGRES_ADMIN_URL);
  validatePostgresUrl(values.AGENTPASS_TEST_POSTGRES_ADMIN_URL);
  return Object.freeze({ ...values });
}

export function buildTestEnvironment(base, fixtureEnvironment) {
  if (!base || typeof base !== "object") throw new TypeError("base environment is required");
  const scenario = optionalLiveBrowserScenario(base.P0B_LIVE_BROWSER_SCENARIO);
  return Object.freeze({
    ...qualificationBaseEnvironment(base),
    ...fixtureEnvironment,
    // A caller's stale disable flag must not turn this live qualification into
    // a successful-looking skipped test.
    P0B_DISABLE_EXTERNAL: "false",
    ...(scenario === undefined ? {} : { P0B_LIVE_BROWSER_SCENARIO: scenario })
  });
}

function optionalLiveBrowserScenario(value) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") throw new OrchestrationError("invalid_browser_scenario", "browser scenario filter is invalid");
  const scenario = value.trim();
  if (!LIVE_BROWSER_SCENARIO_PATTERN.test(scenario) || scenario.length > LIVE_BROWSER_SCENARIO_MAX_LENGTH) {
    throw new OrchestrationError("invalid_browser_scenario", "browser scenario filter is invalid");
  }
  return scenario;
}

export function stableReason(error) {
  const code = typeof error?.code === "string" ? error.code : "error";
  return /^[a-z][a-z0-9_]*$/u.test(code) ? code : "error";
}

export function liveBrowserFailureReason(result) {
  const reason = stableReason({ code: result?.reason });
  const diagnostic = result?.internal?.safe_failure_code;
  if (result?.internal?.timed_out === true || typeof diagnostic !== "string") return reason;
  return `child_exit_nonzero_${diagnostic}`;
}

export function usage() {
  return `Usage: node scripts/p0b/run-live-process.mjs [options]

Starts the existing PostgreSQL TLS fixture, runs the live Console/Cloud/
PostgreSQL process qualification, and always stops the fixture.

Options:
  --fixture-timeout-ms <integer>  PostgreSQL fixture readiness timeout
  --fixture-image <image>        PostgreSQL 17 image override
  --report-output <absolute>     qualification report output path
  --help                         Show this help
`;
}

export async function main(argv = process.argv.slice(2)) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    emitFailure("arguments", error);
    return 1;
  }
  if (options.help) {
    process.stdout.write(usage());
    return 0;
  }

  let sourceBefore;
  let sourceTreeBefore;
  let reportOutput;
  try {
    reportOutput = resolveQualificationOutput(options.reportOutput, process.env.P0B_QUALIFICATION_OUTPUT);
    await prepareQualificationOutput(reportOutput);
    sourceBefore = resolveSourceState(REPOSITORY_ROOT);
    sourceTreeBefore = resolveSourceTree(REPOSITORY_ROOT);
  } catch (error) {
    emitFailure("source", error);
    return 1;
  }

  const startedAt = new Date().toISOString();
  const orchestrationRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "agentpass-p0b-run-"));
  const manifestFile = path.join(orchestrationRoot, "fixture.manifest.json");
  let manifest;
  let failure;
  let interrupted = false;
  let activeChild;
  let terminateActiveChild;
  let publicManifest;
  let fixtureEnvironment;
  let postgresEvidence;
  let browserEvidence;
  let consoleArtifact;
  const commands = [];
  const onSignal = (signal) => {
    interrupted = true;
    if (activeChild && !activeChild.killed) terminateActiveChild?.();
    // Keep the handler installed until the finally block so the fixture is
    // stopped before the process returns control to the shell.
    void signal;
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  try {
    try {
      manifest = await startFixture({
        outputFile: manifestFile,
        timeoutMs: options.fixtureTimeoutMs,
        ...(options.fixtureImage ? { image: options.fixtureImage } : {})
      });
      if (interrupted) throw new OrchestrationError("interrupted");
    } catch (error) {
      failure = { stage: "fixture-start", error };
    }

    if (!failure) {
      try {
        publicManifest = await readManifest(manifestFile, manifest);
        fixtureEnvironment = await readProtectedEnvironment(publicManifest.env_file);
        if (fixtureEnvironment.P0B_POSTGRES_TLS_STATE_FILE !== publicManifest.state_file
          || fixtureEnvironment.P0B_POSTGRES_CA_FILE !== publicManifest.ca_file
          || fixtureEnvironment.P0B_POSTGRES_TLS_IMAGE !== publicManifest.image
          || fixtureEnvironment.P0B_POSTGRES_TLS_CONTAINER_ID !== publicManifest.container_id) {
          throw new OrchestrationError("fixture_manifest_mismatch");
        }
      } catch (error) {
        failure = { stage: "fixture-env", error };
      }
    }

    if (!failure) {
      try {
        postgresEvidence = await collectFixtureProvenance({
          manifest: publicManifest,
          adminUrl: fixtureEnvironment.P0B_POSTGRES_ADMIN_URL,
          caFile: fixtureEnvironment.P0B_POSTGRES_CA_FILE
        });
      } catch (error) {
        failure = { stage: "postgres-provenance", error };
      }
    }

    if (!failure) {
      const result = await runQualificationCommand("npm", ["run", "build"], {
        cwd: CONSOLE_ROOT,
        env: qualificationBaseEnvironment(process.env),
        timeoutMs: BUILD_TIMEOUT_MS,
        onChild: (child, terminate) => { activeChild = child; terminateActiveChild = terminate; }
      });
      commands.push(commandEvidence("console-build", ["npm", "run", "build"], "apps/web-console", result));
      activeChild = undefined;
      terminateActiveChild = undefined;
      if (result.status !== "passed") {
        failure = { stage: "console-build", error: new OrchestrationError(result.reason) };
      }
    }

    if (!failure) {
      try {
        consoleArtifact = await digestArtifactTree(path.join(CONSOLE_ROOT, "dist"), { name: "console-dist", kind: "build" });
        browserEvidence = await collectBrowserMetadata({ chromium });
      } catch (error) {
        failure = { stage: "build-provenance", error };
      }
    }

    if (!failure) {
      try {
        if (interrupted) throw new OrchestrationError("interrupted");
        const childArgs = ["--test", "--test-reporter", "tap", path.relative(REPOSITORY_ROOT, LIVE_BROWSER_TEST)];
        const result = await runQualificationCommand(process.execPath, childArgs, {
          cwd: REPOSITORY_ROOT,
          env: {
            ...buildTestEnvironment(process.env, fixtureEnvironment),
            P0B_LIVE_BROWSER: "1",
            P0B_SOURCE_COMMIT: sourceBefore.commit,
            P0B_SOURCE_TREE: sourceTreeBefore
          },
          timeoutMs: BROWSER_TIMEOUT_MS,
          safeFailureMarkers: LIVE_BROWSER_SAFE_FAILURE_MARKERS,
          terminateOnSafeFailure: true,
          onChild: (child, terminate) => { activeChild = child; terminateActiveChild = terminate; }
        });
        commands.push(commandEvidence("browser-e2e", ["node", ...childArgs], "repository", result));
        activeChild = undefined;
        terminateActiveChild = undefined;
        if (result.status !== "passed") {
          // A provisional TAP marker is useful only while the child is still
          // alive long enough to emit a more specific marker. If the command
          // itself reaches its hard deadline, preserve that timeout instead of
          // misreporting it as a normal nonzero admin/revoke failure.
          const reason = liveBrowserFailureReason(result);
          emitCommandDiagnostic("live-browser", result);
          failure = { stage: "live-browser", error: new OrchestrationError(reason) };
        } else if (interrupted) {
          failure = { stage: "live-browser", error: new OrchestrationError("interrupted") };
        }
      } catch (error) {
        emitSupervisorDiagnostic("live-browser", error);
        failure = { stage: "live-browser", error };
      }
    }

    if (!failure) {
      try {
        if (interrupted) throw new OrchestrationError("interrupted");
        const childArgs = ["--test", "--test-reporter", "tap", "test/p0b-live-process.integration.test.mjs"];
        const result = await runQualificationCommand(process.execPath, childArgs, {
          cwd: REPOSITORY_ROOT,
          env: buildTestEnvironment(process.env, fixtureEnvironment),
          timeoutMs: PROCESS_TIMEOUT_MS,
          onChild: (child, terminate) => { activeChild = child; terminateActiveChild = terminate; }
        });
        commands.push(commandEvidence("process-e2e", ["node", ...childArgs], "repository", result));
        activeChild = undefined;
        terminateActiveChild = undefined;
        if (result.status !== "passed") {
          emitCommandDiagnostic("live-test", result);
          failure = { stage: "live-test", error: new OrchestrationError(result.reason) };
        } else if (interrupted) {
          failure = { stage: "live-test", error: new OrchestrationError("interrupted") };
        }
      } catch (error) {
        failure = { stage: "live-test", error };
      }
    }

    if (!failure) {
      try {
        const afterArtifact = await digestArtifactTree(path.join(CONSOLE_ROOT, "dist"), { name: "console-dist-after", kind: "build-verification" });
        if (afterArtifact.sha256 !== consoleArtifact.sha256 || afterArtifact.bytes !== consoleArtifact.bytes) {
          throw new OrchestrationError("build_artifact_changed");
        }
        const sourceAfter = resolveSourceState(REPOSITORY_ROOT);
        if (sourceAfter.commit !== sourceBefore.commit) throw new OrchestrationError("source_commit_changed");
      } catch (error) {
        failure = { stage: "final-provenance", error };
      }
    }
  } catch (error) {
    failure ??= { stage: "orchestration", error };
  } finally {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    let cleanupFailure;
    if (manifest?.state_file) {
      try {
        await stopFixture(manifest.state_file);
      } catch (error) {
        cleanupFailure = error;
      }
    }
    await fsp.rm(orchestrationRoot, { recursive: true, force: true }).catch(() => {});
    if (cleanupFailure && !failure) failure = { stage: "fixture-stop", error: cleanupFailure };
    if (cleanupFailure && failure) failure.cleanup = true;
  }

  if (failure) {
    emitFailure(failure.stage, failure.error, failure.cleanup);
    return 1;
  }
  try {
    const completedAt = new Date().toISOString();
    const report = buildP0BQualificationReport({
      source_commit: sourceBefore.commit,
      started_at: startedAt,
      completed_at: completedAt,
      commands,
      postgres: postgresEvidence,
      browser: browserEvidence,
      artifacts: [consoleArtifact],
      gates: [
        gateEvidence("build-integrity", { source_commit: sourceBefore.commit, command: commands[0].result, artifact: consoleArtifact }),
        gateEvidence("browser-flow", { source_commit: sourceBefore.commit, command: commands[1].result, browser: browserEvidence, artifact: consoleArtifact }),
        gateEvidence("process-flow", { source_commit: sourceBefore.commit, command: commands[2].result, postgres: postgresEvidence, artifact: consoleArtifact })
      ]
    }, { repositoryRoot: REPOSITORY_ROOT });
    await writeP0BQualificationReport(reportOutput, report);
    process.stdout.write(`p0b-qualification: ${report.report_digest}\n`);
  } catch (error) {
    emitFailure("qualification-report", error);
    return 1;
  }
  process.stdout.write("p0b-orchestration: pass\n");
  return 0;
}

async function readManifest(file, fallback) {
  let parsed;
  try {
    parsed = JSON.parse(await fsp.readFile(file, "utf8"));
  } catch {
    throw new OrchestrationError("invalid_manifest");
  }
  const value = parsed && typeof parsed === "object" ? parsed : fallback;
  if (!value || typeof value.env_file !== "string" || typeof value.state_file !== "string"
    || typeof value.ca_file !== "string" || !path.isAbsolute(value.env_file)
    || !path.isAbsolute(value.state_file) || !path.isAbsolute(value.ca_file)) {
    throw new OrchestrationError("invalid_manifest");
  }
  return value;
}

function validatePostgresUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new OrchestrationError("invalid_env_file");
  }
  if (url.protocol !== "postgresql:" || !url.hostname || !url.username || !url.password
    || url.searchParams.get("sslmode") !== "verify-full" || [...url.searchParams.keys()].length !== 1) {
    throw new OrchestrationError("invalid_env_file");
  }
}

export function qualificationBaseEnvironment(base) {
  if (!base || typeof base !== "object") throw new TypeError("base environment is required");
  const result = Object.create(null);
  const exact = new Set(["PATH", "HOME", "TMPDIR", "LANG", "CI", "NO_COLOR", "PLAYWRIGHT_BROWSERS_PATH"]);
  for (const [key, value] of Object.entries(base)) {
    if ((exact.has(key) || key.startsWith("LC_")) && typeof value === "string") result[key] = value;
  }
  return result;
}

export function resolveQualificationOutput(argument, environment) {
  const value = argument ?? environment ?? DEFAULT_REPORT_OUTPUT;
  if (!isSafeAbsolutePath(value)) throw new OrchestrationError("invalid_report_output");
  return path.resolve(value);
}

export async function prepareQualificationOutput(outputFile) {
  if (!isSafeAbsolutePath(outputFile)) throw new OrchestrationError("invalid_report_output");
  const directory = path.dirname(outputFile);
  await fsp.mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await fsp.lstat(directory);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0 || (uid !== undefined && metadata.uid !== uid)) {
    throw new OrchestrationError("unsafe_report_directory");
  }
  try {
    const existing = await fsp.lstat(outputFile);
    if (!existing.isFile() || existing.nlink !== 1 || (existing.mode & 0o077) !== 0 || (uid !== undefined && existing.uid !== uid)) {
      throw new OrchestrationError("unsafe_report_output");
    }
    await fsp.unlink(outputFile);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function commandEvidence(id, argv, cwd, result) {
  return Object.freeze({ id, argv: Object.freeze(argv), cwd, result });
}

// Keep failure triage useful without ever forwarding child output. These
// fields are supervisor-owned numeric/enum metadata only; assertions, URLs,
// credentials, and arbitrary exception text remain discarded by the runner.
function emitCommandDiagnostic(stage, result) {
  const safeStage = /^[a-z][a-z0-9-]{0,31}$/u.test(stage) ? stage : "unknown";
  const exitCode = Number.isSafeInteger(result?.exit_code) ? result.exit_code : "null";
  const signal = typeof result?.signal === "string" ? result.signal : "none";
  const duration = Number.isSafeInteger(result?.duration_ms) ? result.duration_ms : "null";
  const stdoutBytes = Number.isSafeInteger(result?.stdout_bytes) ? result.stdout_bytes : "null";
  const stderrBytes = Number.isSafeInteger(result?.stderr_bytes) ? result.stderr_bytes : "null";
  const marker = typeof result?.internal?.safe_failure_code === "string"
    ? result.internal.safe_failure_code : "none";
  process.stderr.write(`p0b-command: stage=${safeStage} exit=${exitCode} signal=${signal} duration_ms=${duration} stdout_bytes=${stdoutBytes} stderr_bytes=${stderrBytes} marker=${marker}\n`);
}

function emitSupervisorDiagnostic(stage, error) {
  const safeStage = /^[a-z][a-z0-9-]{0,31}$/u.test(stage) ? stage : "unknown";
  const name = typeof error?.name === "string" && /^[A-Za-z][A-Za-z0-9_]{0,31}$/u.test(error.name) ? error.name : "Error";
  const code = typeof error?.code === "string" && /^[A-Z][A-Z0-9_]{0,47}$/u.test(error.code) ? error.code : "none";
  process.stderr.write(`p0b-supervisor: stage=${safeStage} class=${name} code=${code}\n`);
}

function gateEvidence(id, metadata) {
  return Object.freeze({ id, status: "passed", evidence_sha256: evidenceDigest(metadata) });
}

function isSafeAbsolutePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 && path.isAbsolute(value)
    && !value.includes("\u0000") && !value.includes("\n") && !value.includes("\r");
}

function emitFailure(stage, error, cleanup = false) {
  const reason = stableReason(error);
  process.stderr.write(`p0b-orchestration: fail stage=${stage} reason=${reason}${cleanup ? " cleanup=failed" : ""}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => { process.exitCode = code; }).catch(() => {
    emitFailure("orchestration", new OrchestrationError("error"));
    process.exitCode = 1;
  });
}
