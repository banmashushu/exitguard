import Foundation
import Security
import Darwin

// Read-only native process snapshot. Unknown live-process metadata denies
// readiness rather than guessing that the process is unrelated. No process is
// killed, signalled, suspended or repurposed.
func protectedProcessStarts(policy: FilterPolicy) throws -> [Double] {
    let estimated = proc_listallpids(nil, 0)
    guard estimated > 0, estimated < 1_000_000 else { throw FilterFailure.invalid("Unable to enumerate running processes") }
    var pids = [Int32](repeating: 0, count: Int(estimated) + 1024)
    let bytes = Int32(pids.count * MemoryLayout<Int32>.size)
    let actual = proc_listallpids(&pids, bytes)
    guard actual >= 0, actual < pids.count else { throw FilterFailure.invalid("Process list changed too quickly to attest coverage") }
    var starts: [Double] = []
    for pid in pids.prefix(Int(actual)) where pid > 0 {
        var pathBytes = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &pathBytes, UInt32(pathBytes.count)) > 0 else {
            // libproc reports ESRCH for exited/corpse processes that may still
            // appear in the PID list. signal-0 can continue to find such PIDs;
            // it is not evidence that an executable remains able to run.
            let failure = errno
            if failure == ESRCH { continue }
            // Report which process and errno blocked the scan; the policy is unchanged.
            var nameBytes = [CChar](repeating: 0, count: 256)
            let name = proc_name(pid, &nameBytes, UInt32(nameBytes.count)) > 0 ? String(cString: nameBytes) : "unknown"
            throw FilterFailure.invalid("A live executable path could not be inspected (pid \(pid), \(name), errno \(failure) \(String(cString: strerror(failure))))")
        }
        let path = URL(fileURLWithPath: String(cString: pathBytes)).resolvingSymlinksInPath().path
        let pathMatches = policy.protects(paths: [path], identifiers: [])
        // Process start times are required only for actual targets. macOS can
        // expose an unrelated system daemon's executable path while denying its
        // proc_bsdinfo to a normal user; that daemon must not disable readiness.
        if !pathMatches && policy.bundleIDs.isEmpty { continue }
        var identifiers: [String] = []
        if !pathMatches && !policy.bundleIDs.isEmpty {
            var dynamic: SecCode?
            var code: SecStaticCode?
            let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
            guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &dynamic) == errSecSuccess, let dynamic,
                  SecCodeCopyStaticCode(dynamic, [], &code) == errSecSuccess, let code,
                  let info = try? codeSigningInfo(code) else {
                if kill(pid, 0) == -1 && errno == ESRCH { continue }
                throw FilterFailure.invalid("A live process signing identity could not be inspected")
            }
            let valid = SecCodeCheckValidity(dynamic, [], nil) == errSecSuccess
            let identifier = info[kSecCodeInfoIdentifier as String] as? String
            guard FilterCodeIdentity(path: path, identifier: identifier, signatureValid: valid).signatureResolved, let identifier else { throw FilterFailure.invalid("A live signing identity is invalid or incomplete; bundle identity coverage cannot be attested") }
            identifiers.append(identifier)
        }
        guard pathMatches || policy.protects(paths: [], identifiers: identifiers) else { continue }
        var before = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, size) == size else {
            if errno == ESRCH { continue }
            throw FilterFailure.invalid("A protected live process could not be inspected; native coverage is unavailable")
        }
        var after = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, size) == size else {
            if errno == ESRCH { continue }
            throw FilterFailure.invalid("A process identity changed while checking coverage")
        }
        guard before.pbi_start_tvsec == after.pbi_start_tvsec, before.pbi_start_tvusec == after.pbi_start_tvusec else { throw FilterFailure.invalid("A PID was reused during coverage inspection") }
        starts.append(Double(before.pbi_start_tvsec) + Double(before.pbi_start_tvusec) / 1_000_000)
    }
    return starts
}
