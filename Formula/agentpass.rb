require "json"

class Agentpass < Formula
  desc "Policy-controlled signing broker for coding agents"
  homepage "https://github.com/Torutesu/AIagentpass"
  url "https://github.com/Torutesu/AIagentpass/archive/b9ed16c8760022a5629304dc7180020ef9448de4.tar.gz"
  version "0.18.0"
  sha256 "c996432ec0649bd1d582168a26331c1428a09b09f50345e8bbc5bb36c688023a"
  license "MIT"

  depends_on macos: :sonoma
  depends_on "node"

  def install
    # The Homebrew channel intentionally installs JavaScript source files as-is.
    # It never invokes npm, builds a native app, or installs a production XPC
    # identity. Production hardware enforcement is distributed by the signed
    # and notarized PKG channel.
    libexec.install "bin", "lib"
    (libexec/"packages/protocol").install "packages/protocol/src"
    (libexec/"packages/capability").install "packages/capability/src"
    (libexec/"adapters/mcp-server").install "adapters/mcp-server/bin", "adapters/mcp-server/src"

    node = Formula["node"].opt_bin/"node"
    cli = libexec/"bin/agentpass.mjs"
    broker = libexec/"bin/agentpassd.mjs"

    (bin/"agentpass").write <<~SH
      #!/bin/sh
      set -eu
      node=#{node}
      cli=#{cli}
      export AGENTPASS_DISTRIBUTION=homebrew-evaluation
      export AGENTPASS_PRODUCTION_XPC_BOUNDARY=unavailable

      if [ "${1-}" = "install" ]; then
        printf '%s\n' 'Homebrew is the AgentPass evaluation channel. Install the production native service from the verified, signed, and notarized PKG.' >&2
        exit 2
      fi

      if [ "${1-}" = "status" ] || [ "${1-}" = "doctor" ]; then
        set +e
        output="$("$node" "$cli" "$@")"
        exit_code=$?
        set -e
        if [ -n "$output" ]; then
          if printf '%s\\n' "$output" | "$node" -e '
            let input = "";
            process.stdin.setEncoding("utf8");
            process.stdin.on("data", (chunk) => { input += chunk; });
            process.stdin.on("end", () => {
              const value = JSON.parse(input);
              if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid AgentPass JSON");
              value.distribution = {
                channel: "homebrew",
                mode: "evaluation",
                production_xpc_boundary: false,
                caveat: "Evaluation broker only; use the signed and notarized PKG for the production XPC identity boundary."
              };
              process.stdout.write(`${JSON.stringify(value, null, 2)}\\n`);
            });
          '; then
            exit "$exit_code"
          fi
          printf '%s\\n' "$output"
        fi
        exit "$exit_code"
      fi

      exec "$node" "$cli" "$@"
    SH
    # The onboarding app accepts only a signed executable with the product
    # identity. Homebrew remains the evaluation channel, so this wrapper is
    # deliberately ad-hoc signed with a distinct identity. It must never be
    # accepted as the production Developer ID helper by the onboarding UI.
    # Signing after Homebrew has materialized the wrapper keeps the existing
    # CLI entrypoint and its behavior intact.
    system_command "/usr/bin/codesign",
      args: ["--force", "--sign", "-", "--identifier", "dev.agentpass.homebrew-evaluation", bin/"agentpass"]

    (bin/"agentpassd").write <<~SH
      #!/bin/sh
      set -eu
      export AGENTPASS_DISTRIBUTION=homebrew-evaluation
      export AGENTPASS_PRODUCTION_XPC_BOUNDARY=unavailable
      exec #{node} #{broker} "$@"
    SH

    bin.install_symlink libexec/"bin/agentpass-git-sign.mjs" => "agentpass-git-sign"
    bin.install_symlink libexec/"bin/agentpass-pre-push.mjs" => "agentpass-pre-push"
    bin.install_symlink libexec/"bin/agentpass-anchor.mjs" => "agentpass-anchor"
    bin.install_symlink libexec/"adapters/mcp-server/bin/agentpass-mcp.mjs" => "agentpass-mcp"
  end

  test do
    ENV["HOME"] = (testpath/"home").to_s
    (testpath/"home").mkpath

    system bin/"agentpass", "init"

    status = JSON.parse(shell_output("#{bin}/agentpass status"))
    assert_equal "homebrew", status.dig("distribution", "channel")
    assert_equal "evaluation", status.dig("distribution", "mode")
    assert_equal false, status.dig("distribution", "production_xpc_boundary")

    doctor = JSON.parse(shell_output("#{bin}/agentpass doctor", 1))
    assert_equal "homebrew", doctor.dig("distribution", "channel")
    assert_equal "evaluation", doctor.dig("distribution", "mode")
    assert_equal false, doctor.dig("distribution", "production_xpc_boundary")

    assert_predicate bin/"agentpass-mcp", :exist?
    assert_predicate bin/"agentpass-anchor", :exist?
    assert_match "evaluation channel", shell_output("#{bin}/agentpass install 2>&1", 2)
  end
end
