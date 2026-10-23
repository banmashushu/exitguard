import Foundation
import Security
import Darwin

func codeSigningInfo(_ code: SecStaticCode) throws -> [String: Any] {
    var raw: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
          let info = raw as? [String: Any] else { throw FilterFailure.invalid("Code signing metadata is unavailable") }
    return info
}

func appleRequirement(identifier: String, team: String) -> String {
    "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(team)\""
}

func verifySignedCode(at url: URL, identifier: String, team: String) throws {
    var code: SecStaticCode?
    var requirement: SecRequirement?
    let text = appleRequirement(identifier: identifier, team: team)
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
          SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
          let code,
          SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess else {
        throw FilterFailure.invalid("The installed component does not match the Apple signing team and identifier")
    }
}

func ownSigningTeam(identifier: String) throws -> String {
    var dynamic: SecCode?
    var code: SecStaticCode?
    guard SecCodeCopySelf([], &dynamic) == errSecSuccess, let dynamic,
          SecCodeCopyStaticCode(dynamic, [], &code) == errSecSuccess, let code else { throw FilterFailure.invalid("The running component has no code identity") }
    let info = try codeSigningInfo(code)
    guard let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
          team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
          let path = info[kSecCodeInfoMainExecutable as String] as? URL else { throw FilterFailure.invalid("A real Apple signing team is required; ad-hoc signing is unsupported") }
    try verifySignedCode(at: path, identifier: identifier, team: team)
    return team
}

// Security resolves the complete kernel audit token, including the process
// generation. A numeric PID or cached PID/path pair is never accepted as proof.
func flowIdentity(auditToken: Data) -> FilterCodeIdentity? {
    guard auditToken.count == 32 else { return nil }
    var token = audit_token_t()
    withUnsafeMutableBytes(of: &token) { _ = auditToken.copyBytes(to: $0) }
    var path = [CChar](repeating: 0, count: 4096)
    // Resolve the kernel's actual executable path, independent of the spelling
    // used to open it. The complete token prevents numeric PID reuse.
    guard proc_pidpath_audittoken(&token, &path, UInt32(path.count)) > 0 else { return nil }
    let executablePath = String(cString: path)
    var dynamic: SecCode?
    var code: SecStaticCode?
    let attributes = [kSecGuestAttributeAudit as String: auditToken] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &dynamic) == errSecSuccess, let dynamic,
          SecCodeCopyStaticCode(dynamic, [], &code) == errSecSuccess, let code,
          let info = try? codeSigningInfo(code) else {
        return FilterCodeIdentity(path: executablePath, identifier: nil, signatureValid: false)
    }
    let identifier: String?
    let valid = SecCodeCheckValidity(dynamic, [], nil) == errSecSuccess
    if valid { identifier = info[kSecCodeInfoIdentifier as String] as? String } else { identifier = nil }
    return FilterCodeIdentity(path: executablePath, identifier: identifier, signatureValid: valid)
}

func canonicalExecutablePath(_ path: String) throws -> String {
    let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw FilterFailure.invalid("Protected executable cannot be opened safely") }
    defer { close(descriptor) }
    var information = stat()
    guard fstat(descriptor, &information) == 0, information.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), access(path, X_OK) == 0 else { throw FilterFailure.invalid("Protected target must be a regular executable file") }
    var canonical = [CChar](repeating: 0, count: 4096)
    guard fcntl(descriptor, F_GETPATH, &canonical) == 0 else { throw FilterFailure.invalid("Protected executable's canonical path is unavailable") }
    return String(cString: canonical)
}
