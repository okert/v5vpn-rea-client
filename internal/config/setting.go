package config

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hygkui/v5vpn-rea-client/internal/crypto"
)

// Configuration filenames for local directory
const (
	SettingXMLFilename = "setting.xml"
)

// Raw XML structures matching V5VPN setting.xml
type SettingInfoXML struct {
	XMLName xml.Name    `xml:"SETTING_INFO"`
	Common  CommonXML   `xml:"COMMON"`
	Gateway GatewayList `xml:"GATEWAY"`
}

type CommonXML struct {
	OffRelogin int `xml:"offRelogin,attr"`
	HideToTray int `xml:"HideToTray,attr"`
	LoginDebug int `xml:"LoginDebug,attr"`
	Language   int `xml:"language,attr"`
	Remember   int `xml:"remember,attr"`
	AutoLogin  int `xml:"autologin,attr"`
	TrayNotify int `xml:"trayNotify,attr"`
}

type GatewayList struct {
	LastUseGateway string       `xml:"LastUseGateway,attr"`
	Gateways       []GatewayXML `xml:",any"`
}

type GatewayXML struct {
	XMLName xml.Name `xml:""`
	Name    string   `xml:"Name,attr"`
	IP      string   `xml:"Ip,attr"`
	Port    int      `xml:"Port,attr"`
	Algo    int      `xml:"algo,attr"` // 0: Standard, 1: GM/国密
	User    UserList `xml:"USER"`
}

type UserList struct {
	LastUserName  string    `xml:"LastUserName,attr"`
	AuthType      int       `xml:"authtype,attr"`
	CertType      int       `xml:"certtype,attr"`
	CertAutoLogin int       `xml:"certautologin,attr"`
	Users         []UserXML `xml:",any"`
}

type UserXML struct {
	XMLName xml.Name `xml:""`
	Name    string   `xml:"Name,attr"` // base64
	Pwd     string   `xml:"Pwd,attr"`  // DES-CBC base64
	RPwd    int      `xml:"rpwd,attr"`
	Auto    int      `xml:"auto,attr"`
}

// UserAccount represents a decrypted user profile
type UserAccount struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
	Auto     bool   `json:"auto"`
}

// GatewayProfile represents a VPN Gateway configuration
type GatewayProfile struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	IP            string        `json:"ip"`
	Port          int           `json:"port"`
	Algo          int           `json:"algo"` // 0: Standard, 1: 国密
	LastUserName  string        `json:"lastUserName"`
	SavedAccounts []UserAccount `json:"savedAccounts"`
}

// AppConfig represents application settings used by the client
type AppConfig struct {
	SourcePath     string           `json:"sourcePath"`
	LastUseGateway string           `json:"lastUseGateway"`
	AutoLogin      bool             `json:"autoLogin"`
	Remember       bool             `json:"remember"`
	HideToTray     bool             `json:"hideToTray"`
	Gateways       []GatewayProfile `json:"gateways"`
}

// userDataDir is the per-user application data directory where the
// production build (mygo.App.Path(PathUserData)) writes and reads
// setting.xml. It defaults to "" which means "no candidate" so the
// callers fall back to the working directory / exe directory /
// configs/ candidates. main.go sets this once on startup via
// SetUserDataDir.
var userDataDir string

// SetUserDataDir tells the config package which directory to prefer when
// loading setting.xml. The directory is created if it does not already
// exist. Pass an empty string to fall back to the legacy candidates.
func SetUserDataDir(dir string) {
	userDataDir = dir
}

// DefaultUserDataDir is where saved gateways and accounts live. It does not
// depend on the desktop framework having started, so a config written on
// one launch is found on the next.
func DefaultUserDataDir() string {
	if userDataDir != "" {
		return userDataDir
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "v5vpn-rea")
	case "windows":
		if app := os.Getenv("APPDATA"); app != "" {
			return filepath.Join(app, "v5vpn-rea")
		}
		return filepath.Join(home, "AppData", "Roaming", "v5vpn-rea")
	default:
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return filepath.Join(xdg, "v5vpn-rea")
		}
		return filepath.Join(home, ".local", "share", "v5vpn-rea")
	}
}

// configCandidates returns the paths searched, in order, for a config file.
// Production installs prefer the per-user data directory (mygo
// PathUserData) so an auto-update does not stomp the saved credentials
// when the application directory is replaced. The working directory,
// the executable directory, and configs/ remain as fallbacks so the
// developer workflow and tests still work out of the box.
func configCandidates() []string {
	candidates := []string{}
	if dir := DefaultUserDataDir(); dir != "" {
		candidates = append(candidates, filepath.Join(dir, SettingXMLFilename))
	}
	candidates = append(candidates, SettingXMLFilename)
	if exePath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exePath), SettingXMLFilename))
	}
	return append(candidates, filepath.Join("configs", SettingXMLFilename))
}

// UserDataDir returns the configured per-user data directory, or the
// empty string if none has been set.
func UserDataDir() string { return userDataDir }

// SaveSettingXML writes the config back to its source file. If a per-user
// data directory has been configured, the file is created there
// (preserving the location LoadSettingXML picked up on startup) so an
// updater-driven application-directory replacement does not erase the
// operator's saved credentials.
func (cfg *AppConfig) saveToConfiguredPath(targetPath string) error {
	if targetPath == "" {
		dir := DefaultUserDataDir()
		if dir == "" {
			return fmt.Errorf("no user data directory")
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("cannot create user data dir %s: %w", dir, err)
		}
		targetPath = filepath.Join(dir, SettingXMLFilename)
	}
	return cfg.saveToPath(targetPath)
}
func LoadSettingXML(path string) (*AppConfig, error) {
	if path == "" {
		for _, candidate := range configCandidates() {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		path = SettingXMLFilename
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open %s: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read %s: %w", path, err)
	}

	// Standardize encoding to UTF-8
	data = EnsureUTF8(data)

	var raw SettingInfoXML
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse XML in %s: %w", path, err)
	}

	cfg := &AppConfig{
		SourcePath:     path,
		LastUseGateway: raw.Gateway.LastUseGateway,
		AutoLogin:      raw.Common.AutoLogin == 1,
		Remember:       raw.Common.Remember == 1,
		HideToTray:     raw.Common.HideToTray == 1,
		Gateways:       make([]GatewayProfile, 0, len(raw.Gateway.Gateways)),
	}

	for idx, gw := range raw.Gateway.Gateways {
		id := fmt.Sprintf("gw-%d", idx)
		name := gw.Name
		if name == "" {
			name = gw.IP
		}

		profile := GatewayProfile{
			ID:            id,
			Name:          name,
			IP:            gw.IP,
			Port:          gw.Port,
			Algo:          gw.Algo,
			LastUserName:  gw.User.LastUserName,
			SavedAccounts: make([]UserAccount, 0, len(gw.User.Users)),
		}

		for _, u := range gw.User.Users {
			decUser := crypto.DecodeSettingUsername(u.Name)
			decPwd, _ := crypto.DecryptSettingPassword(u.Pwd)
			profile.SavedAccounts = append(profile.SavedAccounts, UserAccount{
				Username: decUser,
				Password: decPwd,
				Remember: u.RPwd == 1,
				Auto:     u.Auto == 1,
			})
		}

		cfg.Gateways = append(cfg.Gateways, profile)
	}

	return cfg, nil
}

// SaveSettingXML serializes AppConfig back to setting.xml. If the
// caller has configured a per-user data directory via SetUserDataDir,
// the file is created there so an updater-driven replacement of the
// application directory does not erase the operator's saved credentials.
func (cfg *AppConfig) SaveSettingXML(targetPath string) error {
	if targetPath == "" {
		return cfg.saveToConfiguredPath("")
	}
	return cfg.saveToPath(targetPath)
}

// saveToPath serializes AppConfig back to setting.xml at the given path.
func (cfg *AppConfig) saveToPath(targetPath string) error {
	if targetPath == "" {
		targetPath = cfg.SourcePath
	}
	if targetPath == "" {
		targetPath = SettingXMLFilename
	}

	raw := SettingInfoXML{
		Common: CommonXML{
			HideToTray: boolToInt(cfg.HideToTray),
			Remember:   boolToInt(cfg.Remember),
			AutoLogin:  boolToInt(cfg.AutoLogin),
		},
		Gateway: GatewayList{
			LastUseGateway: cfg.LastUseGateway,
			Gateways:       make([]GatewayXML, 0, len(cfg.Gateways)),
		},
	}

	for i, gw := range cfg.Gateways {
		gwTag := fmt.Sprintf("Gateway%d", i)
		gwXML := GatewayXML{
			XMLName: xml.Name{Local: gwTag},
			Name:    gw.Name,
			IP:      gw.IP,
			Port:    gw.Port,
			Algo:    gw.Algo,
			User: UserList{
				LastUserName: gw.LastUserName,
				Users:        make([]UserXML, 0, len(gw.SavedAccounts)),
			},
		}

		for j, acc := range gw.SavedAccounts {
			uTag := fmt.Sprintf("User%d", j)
			encUser := crypto.EncodeSettingUsername(acc.Username)
			encPwd, _ := crypto.EncryptSettingPassword(acc.Password)
			gwXML.User.Users = append(gwXML.User.Users, UserXML{
				XMLName: xml.Name{Local: uTag},
				Name:    encUser,
				Pwd:     encPwd,
				RPwd:    boolToInt(acc.Remember),
				Auto:    boolToInt(acc.Auto),
			})
		}

		raw.Gateway.Gateways = append(raw.Gateway.Gateways, gwXML)
	}

	out, err := xml.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}

	header := []byte(xml.Header)
	content := append(header, out...)
	return os.WriteFile(targetPath, content, 0644)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// FindGateway retrieves a gateway by name or ID
func (cfg *AppConfig) FindGateway(identifier string) *GatewayProfile {
	for i := range cfg.Gateways {
		if strings.EqualFold(cfg.Gateways[i].Name, identifier) || cfg.Gateways[i].ID == identifier || cfg.Gateways[i].IP == identifier {
			return &cfg.Gateways[i]
		}
	}
	return nil
}
