package zap

import (
	"github.com/spf13/viper"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"errors"
)

type apiContext struct {
	Name                      string
	Target                    string
	Format                    string
	OpenApiHostnameOverride   string
	IncludeRegularExpressions []string
	ExcludeRegularExpressions []string
}

type apiScanOptions struct {
	RunActiveScan        bool
	ApiScanOptions       []string
	ApiScanConfigContent string
}

type apiAuthentication struct {
	Type                string
	LoginIndicatorRegex string
}

type headerAuthentication struct {
	AuthHeaderName string
	AuthHeaderSite string
}

// Config holds the configuration describing how to run the ZAP tool.
type ApiConfig struct {
	Request              request
	Context              apiContext
	ReportOptions        reportOptions
	ScanOptions          apiScanOptions
	Authentication       apiAuthentication
	HeaderAuthentication headerAuthentication
	FormAuthentication   formAuthentication
	ScriptAuthentication scriptAuthentication
	credential           *Credential // reading credentials from TOML file is unsupported - use SecretsToMount instead
}

func (c *ApiConfig) UseHeaderAuthentication() bool {
	return c.Authentication.Type == "headerAuthentication"
}

func (c *ApiConfig) UseScriptAuthentication() bool {
	return c.Authentication.Type == "scriptAuthentication"
}

func (c *ApiConfig) UseFormAuthentication() bool {
	return c.Authentication.Type == "formAuthentication"
}

func (c *ApiConfig) IsAuthenticationEnabled() bool {
	return (c.UseHeaderAuthentication() || c.UseScriptAuthentication() || c.UseFormAuthentication()) && c.credential != nil
}

func (c *ApiConfig) IsContextAuthRequired() bool {
	return c.IsAuthenticationEnabled() && (c.UseScriptAuthentication() || c.UseFormAuthentication())
}

func (c *ApiConfig) IsContextFileRequired() bool {
	return len(c.Context.IncludeRegularExpressions) > 0 || len(c.Context.ExcludeRegularExpressions) > 0 || c.IsContextAuthRequired()
}

func (c *ApiConfig) IsValid() bool {
	return c.Context.Target != "" && c.Context.Format != ""
}

// GetCredential returns a single ZAP user credentials loaded via a scan request file.
func (c *ApiConfig) GetCredential() Credential {
	return *(c.credential)
}

// ParseConfig reads configuration data from a request file in either the current directory or the config subdirectory.
func ParseApiConfig(configFilePath string) (*ApiConfig, error) {

	dir, filename := filepath.Split(configFilePath)
	extension := filepath.Ext(filename)
	filenameNoExtension := filename[0 : len(filename)-len(extension)]

	var cfg ApiConfig
	viper.SetConfigName(filenameNoExtension)
	viper.AddConfigPath(dir)
	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}
	if err = viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if cfg.Context.Name == "" {
		cfg.Context.Name = "Context"
	}

	if err := loadApiCredentials(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func loadApiCredentials(config *ApiConfig) error {

	credentialsDirectory := config.Request.GetWorkflowSecretsDirectory()
	if credentialsDirectory == "" {
		return nil
	}

	return filepath.Walk(credentialsDirectory, func(filePath string, info os.FileInfo, e error) error {
		if filePath == credentialsDirectory || !info.IsDir() {
			return nil
		}
		if config.credential != nil {
			return errors.New("only one credential can be defined")
		}

		user := ""
		pass := ""

		if config.UseHeaderAuthentication() {
			var err error
			p, err := ioutil.ReadFile(filepath.FromSlash(path.Join(filePath, "header-value")))
			if err != nil {
				return err
			}
			pass = string(p)
		} else {
			u, err := ioutil.ReadFile(filepath.FromSlash(path.Join(filePath, "username")))
			if err != nil {
				return err
			}
			p, err := ioutil.ReadFile(filepath.FromSlash(path.Join(filePath, "password")))
			if err != nil {
				return err
			}
			user = string(u)
			pass = string(p)
		}
		config.credential = &Credential{
			Username: strings.TrimSpace(user),
			Password: strings.TrimSpace(pass),
		}
		return filepath.SkipDir
	})
}