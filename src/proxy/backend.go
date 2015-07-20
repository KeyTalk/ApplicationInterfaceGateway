package proxy

import "fmt"

type Backend struct {
	Subdomain        string `toml:"subdomain"`
	SessionToken     string `toml:"session_token"`
	Host             string `toml:"host"`
	Port             string `toml:"port"`
	AuthURL          string `toml:"auth_url"`
	UsernameKey      string `toml:"username_key"`
	PasswordKey      string `toml:"password_key"`
	CredentialsStore *Credentials
}

func (b *Backend) ToString() string {
	return fmt.Sprintf("%s:%s", b.Host, b.Port)
}
