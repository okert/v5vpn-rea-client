# Changelog

## 0.1.9

- Local SOCKS5 (`127.0.0.1:2080`) and HTTP (`127.0.0.1:2081`) proxy.
  Wide gateway port ranges such as `1-65535` match by range instead of
  being dropped, and destinations outside the authorized resources are
  refused. System routes, DNS and the system proxy are left unchanged.
- Proxy addresses are shown in the menu bar and on the connected page.
- Gateways and remembered accounts are loaded from the user data
  directory on startup.
- The window close button hides the window. A Dock click or the tray
  "显示主界面" item shows it again. Dock Quit exits without a prompt.
- The connected state is a separate page, so the macOS web view does
  not stay blank after login.

## 0.1.1

- "Check for updates" buttons in the login and connected footers
  (same trigger as the tray menu, via `/api/check-updates` or the
  `VPNService.checkForUpdates` IPC call).
- Release flow: workflow publishes automatically once all platform
  builds pass, and takes the release notes from this changelog.

## 0.1.0

Initial public release.

- Password login against V5VPN SSL VPN gateways (protocol v2.0).
- Pull authorized TCP/UDP resources from /vpn/user/portal/intergration.xml.
- HTTP CONNECT tunnel proxy through the gateway with VSG_SESSIONID cookie.
- Heartbeat / keepalive probe.
- Safe logout via /vpn/user/logout.
- MyGo desktop window with adaptive sizing (460x700 login, 720x620
  gateway manager, 1248x832 connected workspace).
- System tray with connection-state icon and right-click menu.
- GitHub Star footer on login and connected views (opens the repo in
  the system browser).
- ed25519-signed self-update from GitHub releases (tray "Check for
  updates...", ~10s after launch).
- Local HTTP bridge at http://127.0.0.1:<port> for browser fallback.
- Credential recovery: -dump-passwords reads and decrypts legacy
  setting.xml / setting.ini from the current directory or the
  executable directory.
- CLI mode: -cli -connect <gateway> -user <u> -pwd <p>.
- README, DISCLAIMER, NOTICE and configs/setting.xml.example so
  operators can bootstrap without checking production data into VCS.
