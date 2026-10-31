import Foundation

// Read-only native integration check. This catches broad scans that incorrectly
// require unrelated system daemons' restricted process metadata, and PID-list
// corpse races that signal-0 does not distinguish from executable processes.
@main struct FilterProcessTests {
    static func main() throws {
        let ownPath = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
        let canonical = try canonicalExecutablePath(ownPath)
        precondition(canonical == ownPath)
        do { _ = try canonicalExecutablePath(URL(fileURLWithPath: ownPath).deletingLastPathComponent().path); fatalError("Directory accepted as a protected executable") } catch {}
        let policy = try FilterPolicy(port: 17890, programs: [ownPath], bundleIDs: []).validated()
        let starts = try protectedProcessStarts(policy: policy)
        precondition(starts.count == 1 && starts[0] > 0, "The read-only scan must identify its own target executable")
        let unrelated = try FilterPolicy(port: 17890, programs: ["/ExitGuard-test-nonexistent/executable"], bundleIDs: []).validated()
        let unrelatedStarts = try protectedProcessStarts(policy: unrelated)
        precondition(unrelatedStarts.isEmpty, "Unrelated processes were incorrectly matched")
        print("Read-only native process snapshot tests passed")
    }
}
