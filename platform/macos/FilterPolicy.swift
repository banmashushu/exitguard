import Foundation
import CryptoKit

let exitGuardFilterIdentifier = "com.exitguard.Filter"
let exitGuardManagerIdentifier = "com.exitguard.app"
let exitGuardStrictBuild = "strict-socket-v1"

enum FilterFailure: Error, LocalizedError {
    case invalid(String)
    var errorDescription: String? { if case .invalid(let text) = self { return text }; return nil }
}

enum FilterDecision { case allow, drop, unknown }

struct FilterCodeIdentity {
    let path: String
    let identifier: String?
    let signatureValid: Bool
    var signatureResolved: Bool { signatureValid && !(identifier?.isEmpty ?? true) }
}

struct FilterPolicy: Codable {
    let port: UInt16
    let programs: [String]
    let bundleIDs: [String]

    private func unique(_ values: [String]) -> [String] {
        Set(values.map { Data($0.utf8) }).sorted { $0.lexicographicallyPrecedes($1) }.map { String(decoding: $0, as: UTF8.self) }
    }

    func validated() throws -> FilterPolicy {
        guard port > 0, !programs.isEmpty || !bundleIDs.isEmpty else { throw FilterFailure.invalid("A nonzero guard port and explicit protected targets are required") }
        guard programs.count + bundleIDs.count <= 256 else { throw FilterFailure.invalid("Too many protected targets") }
        for path in programs {
            guard path.hasPrefix("/"), path.utf8.count <= 4096, !path.contains("\0"), !path.contains("\n"), !path.contains("\r") else { throw FilterFailure.invalid("Protected executable paths must be absolute") }
        }
        let expression = try NSRegularExpression(pattern: "^[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+$")
        for identifier in bundleIDs {
            let range = NSRange(identifier.startIndex..., in: identifier)
            guard identifier.utf8.count <= 255, expression.firstMatch(in: identifier, range: range)?.range == range else { throw FilterFailure.invalid("Invalid signed application identifier") }
        }
        return FilterPolicy(port: port, programs: unique(programs), bundleIDs: unique(bundleIDs))
    }

    // Byte-for-byte compatible with internal/enforce.Hash. No locale, Unicode
    // normalization or case folding is permitted at this security boundary.
    var hash: String {
        var canonical = "ExitGuard.Policy.v1\n\(port)\n"
        for value in unique(programs) { canonical += "p\(value.utf8.count):\(value)\n" }
        for value in unique(bundleIDs) { canonical += "b\(value.utf8.count):\(value)\n" }
        return SHA256.hash(data: Data(canonical.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    func verdict(paths: [String], identifiers: [String], outgoing: Bool, family: Int, socketType: Int, protocolNumber: Int, host: String?, port: UInt16?) -> FilterDecision {
        guard !paths.isEmpty || !identifiers.isEmpty else { return .unknown }
        guard protects(paths: paths, identifiers: identifiers) else { return .allow }
        guard outgoing else { return .drop }
        // IPv6, UDP/QUIC, raw sockets, missing endpoints and every other port
        // are denied. A textual localhost hostname is never accepted.
        return family == 2 && socketType == 1 && protocolNumber == 6 && host == "127.0.0.1" && port == self.port ? .allow : .drop
    }

    func verdict(identities: [FilterCodeIdentity], outgoing: Bool, family: Int, socketType: Int, protocolNumber: Int, host: String?, port: UInt16?) -> FilterDecision {
        if !bundleIDs.isEmpty && identities.contains(where: { !$0.signatureResolved }) { return .unknown }
        return verdict(paths: identities.map(\.path), identifiers: identities.compactMap(\.identifier), outgoing: outgoing, family: family, socketType: socketType, protocolNumber: protocolNumber, host: host, port: port)
    }

    func protects(paths: [String], identifiers: [String]) -> Bool {
        programs.contains { target in paths.contains { Data($0.utf8) == Data(target.utf8) } } || bundleIDs.contains { target in identifiers.contains { Data($0.utf8) == Data(target.utf8) } }
    }
}

// Read-only XPC attestation. Both peers pin Apple signatures and the same team.
@objc protocol ExitGuardFilterHealth {
    func inspect(nonce: String, reply: @escaping (String, String, Bool, String, Double) -> Void)
}

func processStartedUnderFilter(processStart: Double, filterStart: Double) -> Bool {
    filterStart.isFinite && processStart.isFinite && filterStart > 0 && processStart > filterStart
}
