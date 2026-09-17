import js from "@eslint/js";
import globals from "globals";

// Correctness-first lint baseline for production code. Test and release
// tooling are linted separately (see `npm run lint:all`) so this config can
// stay strict where secrets and signing paths live.
const production = [
  "bin/**/*.mjs",
  "lib/**/*.mjs",
  "packages/*/src/**/*.mjs",
  "adapters/*/src/**/*.mjs",
  "adapters/*/bin/**/*.mjs",
  "apps/cloud-api/src/**/*.mjs",
];

const tooling = [
  "test/**/*.mjs",
  "scripts/**/*.mjs",
  "adapters/*/test/**/*.mjs",
  "packages/*/test/**/*.mjs",
  "apps/cloud-api/test/**/*.mjs",
  "native/macos/Qualification/**/*.mjs",
];

export default [
  {
    ignores: [
      "**/node_modules/",
      "native/macos/.build/",
      "coverage/",
      "dist/",
      ".agentpass/",
      ".n3e-release-materializer-*/",
      "apps/web-console/",
    ],
  },
  {
    files: production,
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: globals.node,
    },
    rules: {
      ...js.configs.recommended.rules,
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
      "no-empty": ["error", { allowEmptyCatch: true }],
      // Control-character matching is intentional input validation at the
      // security boundary, not a bug.
      "no-control-regex": "off",
      eqeqeq: ["error", "always", { null: "ignore" }],
      "no-var": "error",
      "prefer-const": "error",
    },
  },
  {
    files: tooling,
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: { ...globals.node },
    },
    rules: {
      ...js.configs.recommended.rules,
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
      "no-empty": ["warn", { allowEmptyCatch: true }],
      "no-control-regex": "off",
      "no-regex-spaces": "warn",
      "no-useless-escape": "warn",
      "no-undef": "warn",
      // Deliberate patterns in test/release tooling (fixed loops, cleanup
      // throws inside finally) — reported, not gated.
      "no-constant-condition": "warn",
      "no-unsafe-finally": "warn",
    },
  },
];
