import Foundation

@main struct FilterPolicyTests {
    static func main() throws {
        let policy = try FilterPolicy(port: 17890, programs: ["/Applications/A.app/A"], bundleIDs: ["com.example.A"]).validated()
        precondition(policy.verdict(paths: ["/Applications/A.app/A"], identifiers: [], outgoing: true, family: 2, socketType: 1, protocolNumber: 6, host: "127.0.0.1", port: 17890) == .allow)
        precondition(policy.verdict(paths: ["/Applications/A.app/A"], identifiers: [], outgoing: true, family: 2, socketType: 2, protocolNumber: 17, host: "127.0.0.1", port: 17890) == .drop)
        precondition(policy.verdict(paths: ["/Applications/A.app/A"], identifiers: [], outgoing: true, family: 30, socketType: 1, protocolNumber: 6, host: "::1", port: 17890) == .drop)
        precondition(policy.verdict(paths: ["/Applications/A.app/A"], identifiers: [], outgoing: true, family: 2, socketType: 1, protocolNumber: 6, host: "8.8.8.8", port: 17890) == .drop)
        precondition(policy.verdict(paths: [], identifiers: ["com.example.A"], outgoing: true, family: 2, socketType: 1, protocolNumber: 6, host: "127.0.0.1", port: 7890) == .drop)
        precondition(policy.verdict(paths: ["/Applications/Office.app/Office"], identifiers: ["com.example.Office"], outgoing: true, family: 2, socketType: 2, protocolNumber: 17, host: "8.8.8.8", port: 53) == .allow)
        precondition(policy.verdict(paths: [], identifiers: [], outgoing: true, family: 2, socketType: 1, protocolNumber: 6, host: "8.8.8.8", port: 443) == .unknown)
        precondition(policy.verdict(paths: ["/Applications/A.app/A"], identifiers: [], outgoing: false, family: 2, socketType: 1, protocolNumber: 6, host: "8.8.8.8", port: 443) == .drop, "An inbound target flow must not send a direct response")
        precondition(policy.verdict(paths: ["/Applications/Office.app/Office"], identifiers: [], outgoing: false, family: 2, socketType: 1, protocolNumber: 6, host: "8.8.8.8", port: 443) == .allow)
        precondition(policy.verdict(paths: [], identifiers: [], outgoing: false, family: 2, socketType: 1, protocolNumber: 6, host: "8.8.8.8", port: 443) == .unknown)
        let reordered = try FilterPolicy(port: 17890, programs: ["/Applications/A.app/A", "/Applications/A.app/A"], bundleIDs: ["com.example.A"]).validated()
        precondition(policy.hash == reordered.hash)
        let changed = try FilterPolicy(port: 17891, programs: policy.programs, bundleIDs: policy.bundleIDs).validated()
        precondition(policy.hash != changed.hash)
        precondition(policy.hash == "8b88939a5bfba92ef6db176a87e9287a8bd73547be8e2394a7ee4f93f4eac2d9")
        precondition(!processStartedUnderFilter(processStart: 100, filterStart: 101))
        precondition(!processStartedUnderFilter(processStart: 101, filterStart: 101))
        precondition(processStartedUnderFilter(processStart: 102, filterStart: 101))
        precondition(!processStartedUnderFilter(processStart: 102, filterStart: 0))
        let identityPolicy = try FilterPolicy(port: 17890, programs: [], bundleIDs: ["com.example.A"]).validated()
        for incomplete in [FilterCodeIdentity(path: "/Applications/A.app/A", identifier: "com.example.A", signatureValid: false), FilterCodeIdentity(path: "/Applications/A.app/A", identifier: nil, signatureValid: true), FilterCodeIdentity(path: "/Applications/A.app/A", identifier: "", signatureValid: true)] {
            precondition(identityPolicy.verdict(identities: [incomplete], outgoing: true, family: 2, socketType: 1, protocolNumber: 6, host: "8.8.8.8", port: 443) == .unknown)
        }
        let complete = FilterCodeIdentity(path: "/Applications/A.app/A", identifier: "com.example.A", signatureValid: true)
        precondition(identityPolicy.verdict(identities: [complete], outgoing: true, family: 2, socketType: 1, protocolNumber: 6, host: "8.8.8.8", port: 443) == .drop)
        for candidate in [FilterPolicy(port: 0, programs: ["/bin/a"], bundleIDs: []), FilterPolicy(port: 17890, programs: [], bundleIDs: []), FilterPolicy(port: 17890, programs: ["relative"], bundleIDs: [])] {
            do { _ = try candidate.validated(); fatalError("invalid policy accepted") } catch {}
        }
        print("Filter policy tests passed")
    }
}
