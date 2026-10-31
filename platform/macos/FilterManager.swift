import Foundation
import NetworkExtension
import SystemExtensions
import Security
import Darwin

private struct ManagerProof: Encodable {
    let active: Bool
    let policyHash: String
    let reason: String
}

private final class FilterManagerRunner: NSObject, OSSystemExtensionRequestDelegate {
    private let manager = NEFilterManager.shared()
    private var policy: FilterPolicy!
    private var team = ""
    private var operation = ""
    private var connection: NSXPCConnection?
    private var finished = false

    func start() {
        do {
            guard CommandLine.arguments.count == 2, ["inspect", "install", "remove"].contains(CommandLine.arguments[1]) else { throw FilterFailure.invalid("Usage: ExitGuardFilterManager inspect|install|remove (policy JSON on stdin)") }
            operation = CommandLine.arguments[1]
            let input = FileHandle.standardInput.readData(ofLength: 65537)
            guard input.count <= 65536 else { throw FilterFailure.invalid("Policy input is too large") }
            policy = try JSONDecoder().decode(FilterPolicy.self, from: input).validated()
            team = try ownSigningTeam(identifier: exitGuardManagerIdentifier)
            let installed = URL(fileURLWithPath: "/Applications/ExitGuard.app/Contents/Library/SystemExtensions/\(exitGuardFilterIdentifier).systemextension")
            try verifySignedCode(at: installed, identifier: exitGuardFilterIdentifier, team: team)
            if operation == "install" {
                try validateTargets()
                guard try protectedProcessStarts(policy: policy).isEmpty else { throw FilterFailure.invalid("Quit all selected applications and their helpers before installing the native filter") }
                FileHandle.standardError.write(Data("Strict ExitGuard deployment: selected executables (all their instances) lose direct networking; individually unidentifiable sockets are also denied and may affect other applications. No VPN, DNS or default route is changed.\n".utf8))
                // The explicit install CLI is the only activation entry point.
                // Ordinary application startup and inspect never submit this.
                let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: exitGuardFilterIdentifier, queue: .main)
                request.delegate = self
                OSSystemExtensionManager.shared.submitRequest(request)
            } else { loadPreferences() }
            DispatchQueue.main.asyncAfter(deadline: .now() + (operation == "install" ? 120 : 10)) { [weak self] in self?.finish(false, "Native filter operation timed out", failure: true) }
        } catch { finish(false, error.localizedDescription, failure: true) }
    }

    private func validateTargets() throws {
        for path in policy.programs {
            let resolved = try canonicalExecutablePath(path)
            guard Data(resolved.utf8) == Data(path.utf8) else { throw FilterFailure.invalid("Use the executable's exact canonical absolute path and letter case") }
        }
    }

    private func loadPreferences() {
        manager.loadFromPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error { self.finish(false, "Unable to read OS filter preferences: " + error.localizedDescription, failure: true); return }
                switch self.operation {
                case "inspect": self.inspectPreferences()
                case "install": self.installPreferences()
                case "remove": self.removePreferences()
                default: self.finish(false, "Invalid native operation", failure: true)
                }
            }
        }
    }

    private func isOwnConfiguration(_ configuration: NEFilterProviderConfiguration?) -> Bool {
        configuration?.filterDataProviderBundleIdentifier == exitGuardFilterIdentifier
    }

    private func installPreferences() {
        if manager.providerConfiguration != nil && !isOwnConfiguration(manager.providerConfiguration) {
            finish(false, "Refusing to replace a filter configuration owned by another product", failure: true); return
        }
        do {
            let configuration = NEFilterProviderConfiguration()
            configuration.filterSockets = true
            configuration.filterBrowsers = false // Explicitly unsupported on macOS.
            configuration.filterDataProviderBundleIdentifier = exitGuardFilterIdentifier
            configuration.vendorConfiguration = ["strictBuild": exitGuardStrictBuild, "policyHash": policy.hash, "policy": try JSONEncoder().encode(policy)]
            manager.providerConfiguration = configuration
            manager.localizedDescription = "ExitGuard — selected applications may only reach the local guard"
            manager.grade = .firewall
            manager.isEnabled = true
            manager.saveToPreferences { [weak self] error in
                DispatchQueue.main.async {
                    guard let self else { return }
                    if let error { self.finish(false, "Unable to save OS filter configuration: " + error.localizedDescription, failure: true); return }
                    self.operation = "inspect"
                    do {
                        guard try protectedProcessStarts(policy: self.policy).isEmpty else { throw FilterFailure.invalid("A selected application started during installation; quit it and inspect again before launching under protection") }
                        self.loadPreferences()
                    } catch { self.finish(false, error.localizedDescription, failure: true) }
                }
            }
        } catch { finish(false, error.localizedDescription, failure: true) }
    }

    private func removePreferences() {
        guard manager.providerConfiguration != nil else { finish(false, "No ExitGuard filter configuration is installed"); return }
        guard isOwnConfiguration(manager.providerConfiguration) else { finish(false, "Refusing to remove a filter owned by another product", failure: true); return }
        manager.removeFromPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error { self.finish(false, "Unable to remove ExitGuard filter: " + error.localizedDescription, failure: true) }
                else { self.finish(false, "ExitGuard OS filter configuration removed; no other filters were changed") }
            }
        }
    }

    private func inspectPreferences() {
        do {
            guard manager.isEnabled, manager.grade == .firewall,
                  let configuration = manager.providerConfiguration, isOwnConfiguration(configuration),
                  configuration.filterSockets, !configuration.filterBrowsers,
                  let vendor = configuration.vendorConfiguration,
                  vendor["strictBuild"] as? String == exitGuardStrictBuild,
                  vendor["policyHash"] as? String == policy.hash,
                  let data = vendor["policy"] as? Data,
                  try JSONDecoder().decode(FilterPolicy.self, from: data).validated().hash == policy.hash else {
                finish(false, "Enabled native filter preferences do not match the exact strict policy"); return
            }
            inspectRunningProvider()
        } catch { finish(false, error.localizedDescription) }
    }

    private func inspectRunningProvider() {
        let nonce = UUID().uuidString
        let connection = NSXPCConnection(machServiceName: team + "." + exitGuardFilterIdentifier, options: .privileged)
        connection.setCodeSigningRequirement(appleRequirement(identifier: exitGuardFilterIdentifier, team: team))
        connection.remoteObjectInterface = NSXPCInterface(with: ExitGuardFilterHealth.self)
        self.connection = connection
        connection.activate()
        let remote = connection.remoteObjectProxyWithErrorHandler { [weak self] _ in DispatchQueue.main.async { self?.finish(false, "Signed strict filter provider is not running or could not be authenticated") } }
        guard let provider = remote as? ExitGuardFilterHealth else { finish(false, "Native provider health interface is unavailable"); return }
        provider.inspect(nonce: nonce) { [weak self] returnedNonce, hash, active, reason, startedAt in
            DispatchQueue.main.async {
                guard let self else { return }
                guard returnedNonce == nonce, hash == self.policy.hash, reason.hasPrefix(exitGuardStrictBuild + ": ") else {
                    self.finish(false, "Running native filter attestation does not match the request"); return
                }
                do {
                    let starts = try protectedProcessStarts(policy: self.policy)
                    guard starts.allSatisfy({ processStartedUnderFilter(processStart: $0, filterStart: startedAt) }) else { throw FilterFailure.invalid("A selected application predates the native filter; quit and restart it to eliminate existing unfiltered sessions") }
                    self.finish(active, active ? "Matching OS preferences and live signed strict socket provider verified; real-device traffic tests remain required" : reason)
                } catch { self.finish(false, error.localizedDescription) }
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in self?.finish(false, "Live native filter attestation timed out") }
    }

    private func finish(_ active: Bool, _ reason: String, failure: Bool = false) {
        guard !finished else { return }; finished = true
        connection?.invalidate()
        let response = ManagerProof(active: active, policyHash: active ? policy.hash : "", reason: reason)
        if let data = try? JSONEncoder().encode(response) { FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10])) }
        Darwin.exit(failure ? 1 : 0)
    }

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension extensionProperties: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        FileHandle.standardError.write(Data("Approve the signed ExitGuard extension in System Settings to continue. Strict mode denies individually unidentified outbound sockets and can affect them.\n".utf8))
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed { loadPreferences() }
        else { finish(false, "System extension activation requires a restart or further OS approval", failure: true) }
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { finish(false, "System extension activation failed: " + error.localizedDescription, failure: true) }
}

@main struct ExitGuardFilterManagerMain {
    static func main() {
        let runner = FilterManagerRunner()
        withExtendedLifetime(runner) { runner.start(); dispatchMain() }
    }
}
