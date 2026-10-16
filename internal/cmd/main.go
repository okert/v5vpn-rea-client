package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/egoist/mygo"
	"github.com/hygkui/v5vpn-rea-client/internal/config"
	"github.com/hygkui/v5vpn-rea-client/internal/service"
)

//go:embed all:ui
var uiEmbedFS embed.FS

// AppVersion MUST match mygo.json "version" (with "v" prefix); the
// TestAppVersionMatchesMygoJSON test fails the build if they drift.
// NOTE: "2.0" is the gateway protocol version (/vpn/version.xml), not the
// app version — do not "fix" this back to v2.0.0.
var AppVersion = "v0.1.11"

var mainWindow *mygo.Window

func init() {
	attachConsole()
}

func main() {
	// Command-line flags
	cliMode := flag.Bool("cli", false, "Run in CLI/headless mode without desktop GUI")
	dumpPasswords := flag.Bool("dump-passwords", false, "Print all decrypted usernames and passwords from V5VPN settings")
	connectGW := flag.String("connect", "", "Connect to gateway by name or IP in CLI mode")
	userFlag := flag.String("user", "", "Username for CLI connection (defaults to remembered user)")
	pwdFlag := flag.String("pwd", "", "Password for CLI connection (defaults to remembered password)")
	httpPort := flag.Int("port", 0, "Serve web UI on custom HTTP port (0 for auto)")
	flag.Parse()

	// Handle password dumping
	if *dumpPasswords {
		runDumpPasswords()
		return
	}

	// Sub-filesystem for UI files (stripping "ui/" prefix)
	uiFS, err := fs.Sub(uiEmbedFS, "ui")
	if err != nil {
		log.Fatalf("Failed to initialize embedded UI: %v", err)
	}

	vpnService := service.NewVPNService(func(msg string) {
		// Log handler for CLI output
		if *cliMode {
			fmt.Println(msg)
		}
	})
	vpnService.SetAppVersion(AppVersion)

	// CLI Connect Mode
	if *cliMode && *connectGW != "" {
		runCLIConnect(vpnService, *connectGW, *userFlag, *pwdFlag)
		return
	}

	// If CLI flag specified with -list
	if *cliMode {
		runCLIList(vpnService)
		return
	}

	// Setup local HTTP server for Webview and browser fallback
	serverPort := 45678
	if *httpPort > 0 {
		serverPort = *httpPort
	}
	actualPort := startHTTPServer(serverPort, uiFS, vpnService)

	// Name the app before Run so PathUserData is ~/Library/Application Support/v5vpn-rea
	// (the same directory DefaultUserDataDir uses) instead of the executable name.
	mygo.App.SetName("v5vpn-rea")

	// Initialize MyGo Desktop Framework
	log.Printf("Starting V5VPN Client with MyGo framework...")
	// Belt-and-braces: even if a quit is triggered by a code path that
	// forgets to call vpnService.Logout(), the OnBeforeQuit hook fires before the process exits
	// and tears the VPN tunnel down so the gateway does not see an
	// orphan session on the next reconnect.
	mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
		if _, err := vpnService.Logout(); err != nil {
			log.Printf("OnBeforeQuit logout error (ignored): %v", err)
		}
	})
	// Tell the config package where the production build stores its
	// saved credentials. mygo.App.Path(PathUserData) returns a per-user
	// directory such as %APPDATA%\Roaming5vpn-rea on Windows or
	// ~/.local/share/v5vpn-rea on Linux. An updater-driven replacement
	// of the application directory no longer erases the operator's
	// saved credentials when the file lives here instead of next to
	// the executable.
	if dataDir, err := mygo.App.Path(mygo.PathUserData); err == nil && dataDir != "" {
		config.SetUserDataDir(dataDir)
	}
	mygo.BindAs("VPNService", vpnService)
	mygo.SetFrontend(uiFS)

	mygo.App.WhenReady(func() {
		win := mygo.NewWindow(mygo.WindowOptions{
			Title:           fmt.Sprintf("V5VPN 现代客户端 %s", AppVersion),
			Width:           980,
			Height:          720,
			URL:             fmt.Sprintf("http://127.0.0.1:%d/index.html", actualPort),
			BackgroundColor: "#0b1120",
		})
		mainWindow = win
		var isExiting bool
		showMain := func() {
			if win == nil {
				return
			}
			win.Show()
			win.Restore()
			win.Focus()
		}

		if win != nil {
			log.Printf("V5VPN desktop window opened successfully.")
			if iconData, err := fs.ReadFile(uiFS, "icon.png"); err == nil && len(iconData) > 0 {
				_ = win.SetIcon(iconData)
			}
			// The window close button hides the window and leaves the VPN
			// running. A real quit (Dock > Quit, Cmd+Q) sets isExiting from
			// OnBeforeQuit before this fires, so the window is allowed to close.
			win.OnClose(func(e *mygo.CloseEvent) {
				if isExiting {
					return
				}
				e.PreventDefault()
				win.Hide()
			})
		}
		mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
			isExiting = true
		})
		// Dock icon click. A hidden window is not "visible", so AppKit does
		// not bring it back on its own.
		mygo.App.OnActivate(func(bool) {
			if !isExiting {
				showMain()
			}
		})

		// Setup System Tray with crisp 32x32 PNG Icon
		tray, trayErr := mygo.NewTray(mygo.TrayOptions{
			Icon:    generateTrayIcon(false),
			Title:   "V5VPN",
			ToolTip: "V5VPN 客户端 (未连接)",
		})
		if trayErr != nil {
			log.Printf("Notice: Tray icon initialization: %v", trayErr)
			return
		}

		// Function to update tray menu with real-time connection status
		updateTray := func() {
			st := vpnService.GetStatus()
			statusStr, _ := st["status"].(string)
			var statusLabel string
			var isConn bool

			socksLabel := "SOCKS5  未连接"
			httpLabel := "HTTP    未连接"
			if statusStr == "Connected" {
				gwName := vpnService.GetConfig().LastUseGateway
				statusLabel = fmt.Sprintf("状态: 已连接 [%s]", gwName)
				isConn = true
				ends, _ := vpnService.LocalProxy()
				if ends.SOCKS != "" {
					socksLabel = "SOCKS5  " + ends.SOCKS
				}
				if ends.HTTP != "" {
					httpLabel = "HTTP    " + ends.HTTP
				}
				tray.SetToolTip(fmt.Sprintf("V5VPN 已连接  SOCKS5 %s", ends.SOCKS))
				_ = tray.SetIcon(generateTrayIcon(true), false)
			} else if statusStr == "Connecting" {
				statusLabel = "状态: 正在连接..."
				tray.SetToolTip("V5VPN - 正在连接...")
				_ = tray.SetIcon(generateTrayIcon(false), false)
			} else {
				statusLabel = "状态: 未连接"
				tray.SetToolTip("V5VPN - 未连接")
				_ = tray.SetIcon(generateTrayIcon(false), false)
			}

			menuItems := []*mygo.MenuItem{
				{
					Label:    statusLabel,
					Disabled: true,
				},
				{
					Label:    socksLabel,
					Disabled: true,
				},
				{
					Label:    httpLabel,
					Disabled: true,
				},
				mygo.Separator(),
				{
					Label: "显示主界面",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						showMain()
					},
				},
				{
					Label: "检查更新...",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						go func() {
							info := vpnService.CheckForUpdates()
							if info.Error != "" {
								res, err := mygo.Dialog.Message(mygo.MessageOptions{
									Parent:  win,
									Title:   "检查更新",
									Message: "检查更新失败",
									Detail:  info.Error,
									Buttons: []string{"确定", "前往 GitHub 查看"},
								})
								if err == nil && res.Button == 1 {
									_ = vpnService.OpenURL(info.ReleaseURL)
								}
								return
							}

							if info.HasUpdate {
								detail := fmt.Sprintf("当前版本: %s\n最新版本: %s\n\n更新说明:\n%s", info.CurrentVersion, info.LatestVersion, info.ReleaseNotes)
								res, err := mygo.Dialog.Message(mygo.MessageOptions{
									Parent:        win,
									Title:         "发现新版本",
									Message:       fmt.Sprintf("发现新版本 %s！", info.LatestVersion),
									Detail:        detail,
									Buttons:       []string{"前往下载", "稍后再说"},
									DefaultButton: 0,
									CancelButton:  1,
								})
								if err == nil && res.Button == 0 {
									_ = vpnService.OpenURL(info.ReleaseURL)
								}
							} else {
								_, _ = mygo.Dialog.Message(mygo.MessageOptions{
									Parent:  win,
									Title:   "检查更新",
									Message: "当前已是最新版本",
									Detail:  fmt.Sprintf("当前版本 %s 已是最新版本，无需更新。", info.CurrentVersion),
									Buttons: []string{"确定"},
								})
							}
						}()
					},
				},
				mygo.Separator(),
			}

			if isConn {
				menuItems = append(menuItems, &mygo.MenuItem{
					Label: "断开 VPN",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						go vpnService.Logout()
					},
				})
			} else {
				menuItems = append(menuItems, &mygo.MenuItem{
					Label: "连接 VPN",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						cfg := vpnService.GetConfig()
						gw := cfg.FindGateway(cfg.LastUseGateway)
						if gw != nil && len(gw.SavedAccounts) > 0 {
							go vpnService.Login(gw.Name, gw.SavedAccounts[0].Username, gw.SavedAccounts[0].Password, "", true, false)
						} else {
							showMain()
						}
					},
				})
			}

			menuItems = append(menuItems,
				mygo.Separator(),
				&mygo.MenuItem{
					Label: "完全退出",
					Click: func(item *mygo.MenuItem, w *mygo.Window) {
						go func() {
							isExiting = true
							_, _ = vpnService.Logout()
							mygo.RunOnMain(func() {
								if win != nil {
									win.Destroy()
								}
								mygo.App.Quit()
								os.Exit(0)
							})
						}()
					},
				},
			)

			tray.SetMenu(mygo.NewMenu(menuItems))
		}

		// Initial menu setup
		updateTray()

		// Left click on tray brings window to front
		tray.OnClick(func() {
			showMain()
		})

		// Right click on tray opens context menu
		tray.OnRightClick(func() {
			tray.PopUpMenu()
		})

		// Update tray reactively on status change without polling
		vpnService.OnStatusChange = func(status string) {
			mygo.RunOnMain(updateTray)
		}
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatalf("MyGo application terminated with error: %v", err)
	}
}

// startHTTPServer starts the local REST and asset server
func startHTTPServer(port int, uiFS fs.FS, vpnService *service.VPNService) int {
	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cfg := vpnService.GetConfig()
		resp := map[string]any{
			"gateways":       cfg.Gateways,
			"lastUseGateway": cfg.LastUseGateway,
			"remember":       cfg.Remember,
			"autoLogin":      cfg.AutoLogin,
			"sourcePath":     cfg.SourcePath,
			"appVersion":     AppVersion,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		st := vpnService.GetStatus()
		st["appVersion"] = AppVersion
		_ = json.NewEncoder(w).Encode(st)
	})

	mux.HandleFunc("/api/window-size", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if mainWindow != nil {
			mygo.RunOnMain(func() {
				switch req.Mode {
				case "login", "connected":
					// Keep the size the window opened at. Resizing the web
					// view on connect left a blank window on macOS.
				case "settings":
					mainWindow.SetSize(720, 620)
					mainWindow.Center()
				}
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			vpnService.ClearLogs()
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vpnService.GetLogs())
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GWID       string `json:"gwId"`
			Username   string `json:"username"`
			Password   string `json:"password"`
			VerifyCode string `json:"verifycode"`
			Remember   bool   `json:"remember"`
			Auto       bool   `json:"auto"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, err := vpnService.Login(req.GWID, req.Username, req.Password, req.VerifyCode, req.Remember, req.Auto)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		_, err := vpnService.Logout()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	mux.HandleFunc("/api/gateways", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(vpnService.GetGateways())
			return
		}
		if r.Method == http.MethodPost {
			var gw config.GatewayProfile
			if err := json.NewDecoder(r.Body).Decode(&gw); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = vpnService.SaveGateway(gw)
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
	})

	mux.HandleFunc("/api/gateways/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			id := strings.TrimPrefix(r.URL.Path, "/api/gateways/")
			_ = vpnService.DeleteGateway(id)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		}
	})

	mux.HandleFunc("/api/open-url", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err := vpnService.OpenURL(req.URL)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	mux.HandleFunc("/api/check-updates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		info := vpnService.CheckForUpdates()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	})

	// Static UI assets
	mux.Handle("/", http.FileServer(http.FS(uiFS)))

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatalf("Failed to bind local HTTP server: %v", err)
		}
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port

	go func() {
		log.Printf("UI Bridge server listening at http://127.0.0.1:%d", actualPort)
		if err := http.Serve(ln, mux); err != nil {
			log.Printf("HTTP server terminated: %v", err)
		}
	}()
	return actualPort
}

// runDumpPasswords dumps decrypted passwords from original installation
func runDumpPasswords() {
	cfg, err := config.LoadSettingXML("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading V5VPN configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("==================================================")
	fmt.Println("   V5VPN 凭证反解与配置提取器 (REA Tool)        ")
	fmt.Println("==================================================")
	fmt.Printf("配置文件路径: %s\n", cfg.SourcePath)
	fmt.Printf("上次使用网关: %s\n\n", cfg.LastUseGateway)

	for i, gw := range cfg.Gateways {
		fmt.Printf("[%d] 网关: %s\n", i+1, gw.Name)
		fmt.Printf("    地址: %s:%d (算法: %s)\n", gw.IP, gw.Port, algoName(gw.Algo))
		if len(gw.SavedAccounts) == 0 {
			fmt.Println("    账号: (无保存的账号)")
		} else {
			fmt.Println("    已解密凭证:")
			for _, acc := range gw.SavedAccounts {
				fmt.Printf("      - 用户名: %-18s 密码: %s (记住: %v, 自动: %v)\n",
					acc.Username, acc.Password, acc.Remember, acc.Auto)
			}
		}
		fmt.Println("--------------------------------------------------")
	}
}

func algoName(a int) string {
	if a == 1 {
		return "国密 GM/SM"
	}
	return "国际标准 TLS"
}

func runCLIList(svc *service.VPNService) {
	gws := svc.GetGateways()
	fmt.Printf("发现 %d 个已配置的网关:\n", len(gws))
	for i, gw := range gws {
		fmt.Printf("  [%d] %-16s %s:%d\n", i+1, gw.Name, gw.IP, gw.Port)
	}
}

func runCLIConnect(svc *service.VPNService, gwName, user, pwd string) {
	gw := svc.Config.FindGateway(gwName)
	if gw == nil {
		fmt.Fprintf(os.Stderr, "未找到网关: %s\n", gwName)
		os.Exit(1)
	}

	if user == "" && len(gw.SavedAccounts) > 0 {
		user = gw.SavedAccounts[0].Username
	}
	if pwd == "" && len(gw.SavedAccounts) > 0 {
		pwd = gw.SavedAccounts[0].Password
	}

	if user == "" || pwd == "" {
		fmt.Fprintln(os.Stderr, "错误: 请指定 -user 和 -pwd")
		os.Exit(1)
	}

	fmt.Printf("正在连接网关 %s (%s:%d), 用户: %s...\n", gw.Name, gw.IP, gw.Port, user)
	res, err := svc.Login(gw.Name, user, pwd, "", true, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "连接失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("连接成功!")
	data, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(data))
	fmt.Println("\n按 Ctrl+C 退出并断开连接...")

	select {}
}
