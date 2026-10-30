package protocol

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hygkui/v5vpn-rea-client/internal/crypto"
)

// Client handles network interaction with V5VPN Gateway
type Client struct {
	BaseURL       string
	GatewayIP     string
	GatewayPort   int
	Algo          int
	HTTPClient    *http.Client
	SessionID     string
	SessionCookie string
	Integration   *IntegrationInfo
	Logger        func(level string, format string, args ...any)
	stopHeartbeat chan struct{}
	mu            sync.Mutex
	isLoggedIn    bool
}

// NewClient creates a new V5VPN gateway protocol client
func NewClient(ip string, port int, algo int, logger func(string, string, ...any)) *Client {
	if logger == nil {
		logger = func(level string, format string, args ...any) {
			// default noop
		}
	}

	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   6 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 6 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Internal VPN gateways often use private/self-signed certs
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
	}

	httpClient := &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   15 * time.Second,
	}

	baseURL := fmt.Sprintf("https://%s:%d", ip, port)

	return &Client{
		BaseURL:       baseURL,
		GatewayIP:     ip,
		GatewayPort:   port,
		Algo:          algo,
		HTTPClient:    httpClient,
		Logger:        logger,
		stopHeartbeat: make(chan struct{}),
	}
}

// Handshake checks gateway version via /vpn/version.xml
func (c *Client) Handshake() (*VersionResponse, error) {
	u := fmt.Sprintf("%s/vpn/version.xml", c.BaseURL)
	c.Logger("INFO", "Connecting to gateway: %s", u)

	resp, err := c.HTTPClient.Get(u)
	if err != nil {
		c.Logger("ERROR", "Handshake failed: %v", err)
		return nil, fmt.Errorf("gateway handshake failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var v VersionResponse
	if err := xml.Unmarshal(body, &v); err != nil {
		c.Logger("WARN", "Failed to parse version.xml: %s, fallback to default", string(body))
		return &VersionResponse{Major: "2", Minor: "0"}, nil
	}

	c.Logger("SUCCESS", "Gateway handshake OK. Version %s.%s", v.Major, v.Minor)
	return &v, nil
}

// Login authenticates user with gateway using AES-128-CBC encrypted credentials
func (c *Client) Login(username, password, verifycode string) (*IntegrationInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Logger("INFO", "Initiating password authentication for user: %s", username)

	// Encrypt username and password using AES-128-CBC
	encUser, err := crypto.EncryptAuthParam(username)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt username: %w", err)
	}
	encPwd, err := crypto.EncryptAuthParam(password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt password: %w", err)
	}

	// In V5VPN protocol (SecController.dll), for version >= 1.0 (such as version 2.0 gateways),
	// credentials are encrypted using AES-128-CBC and encode parameter MUST be "2".
	// encode=1 indicates Base64 encoding only (without AES).
	// Passing encode=1 with AES ciphertext caused gateway to report "用户名或密码错误" (0x8000001A).
	// Format is raw parameter concatenation as implemented in SecController.dll without URL-escaping.
	authBody := fmt.Sprintf("username=%s&password=%s&encode=2&verifycode=%s", encUser, encPwd, verifycode)

	authURL := fmt.Sprintf("%s/vpn/user/auth/password", c.BaseURL)
	req, err := http.NewRequest("POST", authURL, strings.NewReader(authBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "LeadSec VPN Client")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		c.Logger("ERROR", "Auth request failed: %v", err)
		return nil, fmt.Errorf("auth request network error: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	c.Logger("INFO", "Auth response status: %s", resp.Status)

	// Parse XML response body to detect gateway errors
	var authResp AuthResponse
	if err := xml.Unmarshal(respBody, &authResp); err == nil && authResp.Result.Code != "" {
		codeVal, _ := strconv.ParseUint(strings.TrimPrefix(authResp.Result.Code, "0x"), 16, 64)
		if authResp.Result.Code != "0" && authResp.Result.Code != "0x0" && codeVal != 0 {
			errMsg := authResp.Result.Msg
			if errMsg == "" {
				errMsg = "网关拒绝登录认证"
			}
			c.Logger("ERROR", "Gateway authentication failed: %s (code: %s)", errMsg, authResp.Result.Code)
			return nil, fmt.Errorf("登录失败: %s (错误代码: %s)", errMsg, authResp.Result.Code)
		}
	}

	// Check cookies for session ID (VSG_SESSIONID)
	u, _ := url.Parse(c.BaseURL)
	for _, cookie := range c.HTTPClient.Jar.Cookies(u) {
		if strings.EqualFold(cookie.Name, "VSG_SESSIONID") && cookie.Value != "" {
			c.SessionID = cookie.Value
			c.SessionCookie = cookie.String()
			c.Logger("SUCCESS", "Acquired Session ID: %s", c.SessionID)
			break
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed with HTTP status %d: %s", resp.StatusCode, string(respBody))
	}

	if c.SessionID == "" {
		c.Logger("ERROR", "No valid Session ID received from gateway. Response: %s", string(respBody))
		return nil, fmt.Errorf("登录未下发有效会话ID (可能凭证错误或需要图形验证码)")
	}

	// Fetch integration resources
	integration, err := c.fetchIntegrationInfo()
	if err != nil {
		c.Logger("ERROR", "Fetch integration info failed: %v", err)
		return nil, fmt.Errorf("获取内网受保护资源失败: %w", err)
	}

	c.Integration = integration
	c.Logger("SUCCESS", "Login successful! User: %s, Assigned resources: %d",
		integration.User.Name, len(integration.ResourceList.TCPUDPResources))

	c.isLoggedIn = true

	// Start heartbeat
	interval := 180 * time.Second
	if c.Integration != nil && c.Integration.Session.DetectInterval > 0 {
		interval = time.Duration(c.Integration.Session.DetectInterval) * time.Second
	}
	c.startHeartbeatLoop(interval)

	return c.Integration, nil
}

// setRawSessionCookie sends VSG_SESSIONID without RFC 6265 quoting.
//
// LeadSec session ids can contain a comma. net/http's cookie jar then emits
// Cookie: VSG_SESSIONID="a,b". This gateway never answers that request, so
// login stops at "获取内网受保护资源失败" after the client timeout. The id is
// also stored unquoted and attached here so the jar's quoted copy is dropped.
func setRawSessionCookie(req *http.Request, sessionID string) {
	if sessionID == "" || req == nil {
		return
	}
	kept := req.Header["Cookie"][:0]
	for _, line := range req.Header["Cookie"] {
		if !strings.HasPrefix(strings.ToLower(textproto.TrimString(line)), "vsg_sessionid=") {
			kept = append(kept, line)
		}
	}
	raw := "VSG_SESSIONID=" + sessionID
	if len(kept) == 0 {
		req.Header["Cookie"] = []string{raw}
		return
	}
	req.Header["Cookie"] = append(kept, raw)
}

// fetchIntegrationInfo retrieves the integration.xml containing resources and policies
func (c *Client) fetchIntegrationInfo() (*IntegrationInfo, error) {
	reqURL := fmt.Sprintf("%s/vpn/user/portal/intergration.xml?version=2.0", c.BaseURL)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "LeadSec VPN Client")
	// CookieJar quotes values that contain a comma. LeadSec hangs the
	// request when it sees Cookie: VSG_SESSIONID="id,with,comma".
	setRawSessionCookie(req, c.SessionID)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info IntegrationInfo
	if err := xml.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse intergration.xml: %w", err)
	}

	return &info, nil
}

// startHeartbeatLoop runs the periodic detect/keepalive probe
func (c *Client) startHeartbeatLoop(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopHeartbeat:
				return
			case <-ticker.C:
				c.mu.Lock()
				if !c.isLoggedIn {
					c.mu.Unlock()
					return
				}
				c.mu.Unlock()

				probeURL := fmt.Sprintf("%s/vpn/user/portal/intergration.xml?period=%d&version=2.0",
					c.BaseURL, int(interval.Seconds()))
				req, reqErr := http.NewRequest("GET", probeURL, nil)
				if reqErr != nil {
					c.Logger("WARN", "Heartbeat probe failed: %v", reqErr)
					continue
				}
				req.Header.Set("User-Agent", "LeadSec VPN Client")
				setRawSessionCookie(req, c.SessionID)
				resp, err := c.HTTPClient.Do(req)
				if err != nil {
					c.Logger("WARN", "Heartbeat probe failed: %v", err)
				} else {
					resp.Body.Close()
					c.Logger("DEBUG", "Heartbeat keepalive acknowledged (%d)", resp.StatusCode)
				}
			}
		}
	}()
}

// Logout sends logout notification and tears down session
func (c *Client) Logout() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isLoggedIn {
		return nil
	}

	c.Logger("INFO", "Logging out of VPN gateway...")
	select {
	case c.stopHeartbeat <- struct{}{}:
	default:
	}

	logoutURL := fmt.Sprintf("%s/vpn/user/logout", c.BaseURL)
	_, _ = c.HTTPClient.Get(logoutURL)

	c.isLoggedIn = false
	c.SessionID = ""
	c.Integration = nil
	c.Logger("SUCCESS", "Logged out successfully")
	return nil
}

// IsLoggedIn returns login status
func (c *Client) IsLoggedIn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isLoggedIn
}
