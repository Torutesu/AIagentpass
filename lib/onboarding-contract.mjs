/**
 * CLI boundary adapters for the frozen browser-led onboarding contract.
 * The protocol package owns the actual shape and canonicalization so the CLI
 * cannot drift from the OpenAPI/JSON Schema/native DTO contract.
 */
export {
  ONBOARDING_CONTRACT_VERSION,
  ONBOARDING_INVITATION_DELIVERY_TYPE,
  ONBOARDING_TRUST_INSTALLATION_ACK_TYPE,
  normalizeOnboardingControlAcknowledgement,
  normalizeOnboardingInvitation,
  normalizeOnboardingInvitationDelivery,
  normalizeOnboardingPreflight,
  normalizeOnboardingTrustInstallationAcknowledgement,
  parseOnboardingControlAcknowledgementJson,
  parseOnboardingInvitationDeliveryJson,
  parseOnboardingPreflightJson,
  parseOnboardingTrustInstallationAcknowledgementJson
} from "../packages/protocol/src/index.mjs";
