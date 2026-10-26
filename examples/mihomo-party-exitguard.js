// Optional Clash Party (formerly Mihomo Party) JavaScript override.
// Import manually only after your provider confirms a fixed public IPv4.
// Leave empty for a no-op. Use the exact name of ONE existing leaf proxy.
// This does not activate ExitGuard or change rules, groups or system proxy.
let TARGET_PROXY = "";

function main(config) {
  if (TARGET_PROXY === "") return config;
  const fail = () => { throw new Error("ExitGuard: invalid fixed leaf or conflicting listener; configuration was not changed"); };
  if (typeof TARGET_PROXY !== "string" || TARGET_PROXY.trim() !== TARGET_PROXY || /[\r\n\0]/.test(TARGET_PROXY)) fail();
  const builtins = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"];
  if (builtins.includes(TARGET_PROXY.toUpperCase())) fail();
  if (!config || typeof config !== "object" || Array.isArray(config) || !Array.isArray(config.proxies)) fail();
  const groups = config["proxy-groups"] === undefined ? [] : config["proxy-groups"];
  if (!Array.isArray(groups) || groups.some(group => group && group.name === TARGET_PROXY)) fail();
  const targets = config.proxies.filter(proxy => proxy && proxy.name === TARGET_PROXY);
  if (targets.length !== 1) fail();
  const leaf = targets[0];
  // Conservative protocol allowlist: unknown types, relay/group semantics and
  // dialer-proxy chains need separate review, so this example refuses them.
  const protocols = ["ss", "ssr", "vmess", "vless", "trojan", "socks5", "http", "snell", "hysteria", "hysteria2", "tuic", "wireguard", "ssh", "mieru", "anytls"];
  if (!protocols.includes(leaf.type) || leaf["dialer-proxy"] !== undefined) fail();
  const listeners = config.listeners === undefined ? [] : config.listeners;
  if (!Array.isArray(listeners)) fail();
  for (const key of ["port", "socks-port", "mixed-port", "redir-port", "tproxy-port", "external-controller", "external-controller-tls", "external-controller-pipe"]) {
    const value = config[key];
    if (value !== undefined && (String(value) === "17891" || /:17891$/.test(String(value)))) fail();
  }
  const expected = {name: "exitguard-in", type: "http", listen: "127.0.0.1", port: 17891, proxy: TARGET_PROXY, users: []};
  // Mihomo also supports listener port ranges/lists. This small example refuses
  // every non-single-port format rather than guessing whether 17891 is covered.
  for (const listener of listeners) {
    if (!listener || typeof listener !== "object" ||
        !(typeof listener.port === "number" || typeof listener.port === "string") ||
        !/^[1-9][0-9]{0,4}$/.test(String(listener.port)) || Number(listener.port) > 65535) fail();
  }
  const conflicts = listeners.filter(listener => listener && (listener.name === expected.name || String(listener.port) === "17891"));
  if (conflicts.length) {
    const existing = conflicts[0];
    if (conflicts.length !== 1 || Object.keys(existing).length !== Object.keys(expected).length ||
        Object.keys(expected).some(key => key === "users" ? !Array.isArray(existing.users) || existing.users.length !== 0 : existing[key] !== expected[key])) fail();
    return config;
  }
  config.listeners = listeners.concat([expected]);
  return config;
}
