import AppKit
import Foundation
import WebKit

// The shell owns only its bundled, unprivileged Go core. It never launches a
// normal browser, installs a filter, or asks Network Extension for activation.
@main
final class ExitGuardApp: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate {
    private var window: NSWindow!
    private var webView: WKWebView!
    private var core: Process?
    private var output = Data()
    private var readyOrigin: URLComponents?
    private var receivedReady = false
    private var quitting = false

    static func main() {
        let app = NSApplication.shared
        let delegate = ExitGuardApp()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
        withExtendedLifetime(delegate) {}
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        installMenu()
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.allowsBackForwardNavigationGestures = false
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1240, height: 850),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "ExitGuard · 出口守护"
        window.minSize = NSSize(width: 860, height: 650)
        window.contentView = webView
        window.delegate = self
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        showMessage(title: "正在启动本机守护", message: "代理转发默认关闭。填写上游与期望 IP，检查通过后即可启用；严格阻断另需系统部署。")
        startCore()
    }

    private func installMenu() {
        let menu = NSMenu()
        let application = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "退出 ExitGuard", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        application.submenu = appMenu
        menu.addItem(application)
        let edit = NSMenuItem()
        let editMenu = NSMenu(title: "编辑")
        editMenu.addItem(withTitle: "撤销", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "剪切", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "复制", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "粘贴", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "全选", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        edit.submenu = editMenu
        menu.addItem(edit)
        NSApplication.shared.mainMenu = menu
    }

    private func startCore() {
        guard let directory = Bundle.main.executableURL?.deletingLastPathComponent() else {
            showFailure("找不到应用内的守护核心，请重新构建完整的 ExitGuard.app。")
            return
        }
        let executable = directory.appendingPathComponent("exitguard-core")
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            showFailure("守护核心缺失或不可执行，请重新构建完整的 ExitGuard.app。")
            return
        }
        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        process.executableURL = executable
        process.arguments = ["serve", "--no-open", "--ready-json"]
        process.standardOutput = stdout
        process.standardError = stderr
        // Drain stderr without copying URLs or process credentials into logs.
        stderr.fileHandleForReading.readabilityHandler = { handle in
            if handle.availableData.isEmpty { handle.readabilityHandler = nil }
        }
        stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            DispatchQueue.main.async { self?.consumeReady(data) }
        }
        process.terminationHandler = { [weak self] exited in
            stdout.fileHandleForReading.readabilityHandler = nil
            stderr.fileHandleForReading.readabilityHandler = nil
            DispatchQueue.main.async {
                guard let self = self, !self.quitting else { return }
                self.showFailure("守护核心已停止（退出码 \(exited.terminationStatus)）。本机代理已关闭，请退出并重新打开应用；已有系统规则需要单独检查。")
            }
        }
        do { try process.run(); core = process }
        catch { showFailure("本机守护核心未能启动，请检查应用安装和文件权限。") }
    }

    private func consumeReady(_ data: Data) {
        guard !receivedReady else { return }
        output.append(data)
        guard output.count <= 65_536 else { showFailure("守护核心返回的启动消息无效。"); core?.terminate(); return }
        guard let newline = output.firstIndex(of: 10) else { return }
        let line = output.prefix(upTo: newline)
        guard let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              object["ready"] as? Bool == true,
              let raw = object["url"] as? String,
              let parts = URLComponents(string: raw),
              parts.scheme == "http", parts.host == "127.0.0.1",
              let port = parts.port, port > 0, port <= 65535,
              parts.user == nil, parts.password == nil, parts.query == nil,
              parts.path == "/", let fragment = parts.fragment,
              fragment.hasPrefix("token="), fragment.count == 49,
              fragment.dropFirst(6).allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }),
              let url = parts.url else {
            showFailure("守护核心返回的本机地址或会话凭证无效。")
            core?.terminate()
            return
        }
        receivedReady = true
        output.removeAll(keepingCapacity: false)
        readyOrigin = parts
        webView.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData))
    }

    private func showFailure(_ message: String) { showMessage(title: "本机代理尚未就绪", message: message) }
    private func showMessage(title: String, message: String) {
        let escaped = message.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
        webView.loadHTMLString("<!doctype html><html lang='zh-CN'><meta charset='utf-8'><body style='font:15px -apple-system;background:#f6f8f5;color:#234d3e;display:grid;place-content:center;height:85vh;margin:0'><div style='max-width:540px;padding:40px'><p style='font-size:13px;letter-spacing:2px'>EXITGUARD</p><h1 style='font-size:28px'>\(title)</h1><p style='color:#748272;line-height:1.9'>\(escaped)</p></div></body></html>", baseURL: nil)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else { decisionHandler(.cancel); return }
        if url.absoluteString == "about:blank" { decisionHandler(.allow); return }
        guard let origin = readyOrigin, url.scheme == "http", url.host == "127.0.0.1",
              url.port == origin.port, url.user == nil, url.password == nil else {
            decisionHandler(.cancel); return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? { nil }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) {
        quitting = true
        if core?.isRunning == true { core?.terminate() }
    }
}
