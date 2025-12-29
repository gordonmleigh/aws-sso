package config

import (
	"bufio"
	"os"
	"path"
	"strings"
)

type AwsConfig struct {
	Path   string
	config []*configSection
}

type configSection struct {
	Type     string
	Name     string
	Settings []*configSetting
}

type configSetting struct {
	Key   string
	Value string
}

func Open() (*AwsConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cfg := &AwsConfig{
		Path: path.Join(home, ".aws/config"),
	}
	return cfg, cfg.Open()
}

func (c *AwsConfig) Open() error {
	f, err := os.Open(c.Path)
	if os.IsNotExist(err) {
		// if it doesn't exist that's fine, we just have an empty config
		return nil
	}
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(f)
	currentSection := ""
	currentType := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// remove comments
		hashIndex := strings.Index(line, "#")
		if hashIndex >= 0 {
			line = strings.TrimSpace(line[:hashIndex])
		}

		// skip empty lines
		if line == "" {
			continue
		}

		if isSection, sectionType, name := getSectionName(line); isSection {
			currentType = sectionType
			currentSection = name
		} else if isSetting, key, value := getSetting(line); isSetting {
			c.set(currentType, currentSection, key, value)
		}
	}
	return nil
}

func (c *AwsConfig) GetProfiles() []string {
	var profiles []string
	for _, section := range c.config {
		if section.Type == "profile" {
			profiles = append(profiles, section.Name)
		}
	}
	return profiles
}

func (c *AwsConfig) GetProfileSetting(profileName string, key string) string {
	return c.get("profile", profileName, key)
}

func (c *AwsConfig) GetSsoConfig(name string) *SsoConfig {
	return &SsoConfig{
		Name:     name,
		Region:   c.get("sso-session", name, "sso_region"),
		StartUrl: c.get("sso-session", name, "sso_start_url"),
	}
}

func (c *AwsConfig) GetSsoConfigForProfile(profileName string) *SsoConfig {
	cfg := &SsoConfig{
		Name:     c.get("profile", profileName, "sso_session"),
		Region:   c.get("profile", profileName, "sso_region"),
		StartUrl: c.get("profile", profileName, "sso_start_url"),
	}
	if cfg.Name == "" {
		cfg.Name = cfg.StartUrl
	}
	return cfg
}

func (c *AwsConfig) GetSsoProfiles() []string {
	var profiles []string
	for _, section := range c.config {
		if section.Type == "sso-session" {
			profiles = append(profiles, section.Name)
		}
	}
	return profiles
}

func (c *AwsConfig) get(sectionType string, section string, key string) string {
	setting := c.getSetting(sectionType, section, key, false, true)
	if setting == nil {
		return ""
	}
	return setting.Value
}

func (c *AwsConfig) getSection(sectionType string, name string, create bool) *configSection {
	for _, section := range c.config {
		if section.Type == sectionType && section.Name == name {
			return section
		}
	}

	if create {
		section := &configSection{
			Type: sectionType,
			Name: name,
		}
		c.config = append(c.config, section)
		return section
	}
	return nil
}

func (sec *configSection) getSetting(key string, create bool) *configSetting {
	for i := len(sec.Settings) - 1; i >= 0; i-- {
		value := sec.Settings[i]
		if value.Key == key {
			return value
		}
	}

	if create {
		setting := &configSetting{
			Key: key,
		}
		sec.Settings = append(sec.Settings, setting)
		return setting
	}
	return nil
}

func (c *AwsConfig) getSetting(
	sectionType string,
	section string,
	key string,
	create bool,
	recursive bool,
) *configSetting {
	sec := c.getSection(sectionType, section, create)
	if sec == nil {
		return nil
	}

	setting := sec.getSetting(key, create)
	if setting != nil {
		return setting
	}

	if !recursive {
		return nil
	}

	if strings.HasPrefix(key, "sso_") {
		ssoSession := sec.getSetting("sso_session", false)
		if ssoSession != nil {
			setting = c.getSetting("sso-session", ssoSession.Value, key, false, false)
			if setting != nil {
				return setting
			}
		}
	}

	source := sec.getSetting("source_profile", false)
	if source != nil {
		return c.getSetting("profile", source.Value, key, false, true)
	}
	if sectionType != "default" {
		return c.getSetting("default", "", key, false, false)
	}
	return nil
}

func (c *AwsConfig) set(sectionType string, section string, key string, value string) {
	setting := c.getSetting(sectionType, section, key, true, false)
	setting.Value = value
}

type SsoConfig struct {
	Name     string
	Region   string
	StartUrl string
}

func getSetting(line string) (ok bool, key string, value string) {
	parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
	if len(parts) != 2 {
		return false, "", ""
	}

	return true, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func getSectionName(line string) (ok bool, sectionType string, name string) {
	trimmed := strings.TrimSpace(line)

	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return false, "", ""
	}

	inner := strings.TrimSpace(trimmed[1 : len(line)-1])

	parts := strings.SplitN(inner, " ", 2)
	if len(parts) == 1 {
		return true, inner, ""
	}

	return true, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}
