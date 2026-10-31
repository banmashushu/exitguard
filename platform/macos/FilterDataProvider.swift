import Foundation
import Network
import NetworkExtension
import Security
import OSLog

final class FilterDataProvider: NEFilterDataProvider, NSXPCListenerDelegate, ExitGuardFilterHealth {
    private let stateLock = NSLock()
    private var policy: FilterPolicy?
    private var healthy = false
    private var healthReason = "Filter has not started"
    private var startedAt: Double = 0
    private var listener: NSXPCListener?
    private let logger = Logger(subsystem: exitGuardFilterIdentifier, category: "filter")

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        do {
            let team = try ownSigningTeam(identifier: exitGuardFilterIdentifier)
            guard let configuration = filterConfiguration.vendorConfiguration,
                  configuration["strictBuild"] as? String == exitGuardStrictBuild,
                  let raw = configuration["policy"] as? Data else { throw FilterFailure.invalid("An explicit strict policy is required") }
            let configured = try JSONDecoder().decode(FilterPolicy.self, from: raw).validated()
            guard configuration["policyHash"] as? String == configured.hash,
                  filterConfiguration.filterSockets, !filterConfiguration.filterBrowsers else { throw FilterFailure.invalid("Filter configuration does not match the strict socket policy") }
            stateLock.lock(); policy = configured; stateLock.unlock()

            let service = team + "." + exitGuardFilterIdentifier
            let listener = NSXPCListener(machServiceName: service)
            listener.setConnectionCodeSigningRequirement(appleRequirement(identifier: exitGuardManagerIdentifier, team: team))
            listener.delegate = self
            self.listener = listener
            listener.activate()
            // Every socket reaches handleNewFlow; unrelated resolved applications
            // are immediately allowed there. No packet/TUN routing is installed.
            let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
            apply(settings) { [weak self] error in
                guard let self else { completionHandler(FilterFailure.invalid("Filter stopped during startup")); return }
                self.stateLock.lock()
                self.healthy = error == nil
                self.startedAt = error == nil ? Date().timeIntervalSince1970 : 0
                self.healthReason = error?.localizedDescription ?? "Strict socket filter is running"
                self.stateLock.unlock()
                completionHandler(error)
            }
        } catch { completionHandler(error) }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stateLock.lock(); healthy = false; healthReason = "Filter stopped"; stateLock.unlock()
        listener?.invalidate(); listener = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socket = flow as? NEFilterSocketFlow else { return .allow() }
        stateLock.lock(); let current = policy; stateLock.unlock()
        guard let current else { recordUnknown("No strict policy is loaded"); return .drop() }
        let tokens = [flow.sourceAppAuditToken, flow.sourceProcessAuditToken].compactMap { $0 }
        var identities: [FilterCodeIdentity] = []
        guard !tokens.isEmpty else { recordUnknown("A socket has no audit identity"); return .drop() }
        for token in Set(tokens) {
            guard let identity = flowIdentity(auditToken: token) else {
                recordUnknown("A socket identity could not be safely resolved")
                return .drop()
            }
            identities.append(identity)
        }
        let endpoint = socket.remoteEndpoint as? NWHostEndpoint
        let decision = current.verdict(identities: identities, outgoing: flow.direction == .outbound, family: Int(socket.socketFamily), socketType: Int(socket.socketType), protocolNumber: Int(socket.socketProtocol), host: endpoint?.hostname, port: endpoint.flatMap { UInt16($0.port) })
        switch decision {
        case .allow: return .allow()
        case .drop: return .drop()
        case .unknown: recordUnknown("A socket has no complete usable identity"); return .drop()
        }
    }

    private func recordUnknown(_ reason: String) {
        stateLock.lock(); healthy = false; healthReason = reason; stateLock.unlock()
        // No process paths, destination hosts or traffic contents are logged.
        logger.error("An unidentified socket was denied; strict filter health requires review")
    }

    func inspect(nonce: String, reply: @escaping (String, String, Bool, String, Double) -> Void) {
        stateLock.lock(); let hash = policy?.hash ?? ""; let active = healthy; let reason = healthReason; let started = startedAt; stateLock.unlock()
        reply(nonce, hash, active, exitGuardStrictBuild + ": " + reason, started)
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: ExitGuardFilterHealth.self)
        connection.exportedObject = self
        connection.activate()
        return true
    }
}

@main struct ExitGuardFilterMain {
    static func main() {
        autoreleasepool {
            NEProvider.startSystemExtensionMode()
        }
        dispatchMain()
    }
}
