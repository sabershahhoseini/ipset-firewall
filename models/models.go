package models

type Set struct {
	Country string
	SetName string
}
type Rule struct {
	Policy string   `yaml:"policy"`
	Insert int      `yaml:"insert"`
	Type   []string `yaml:"type"`
	Not    bool     `yaml:"not"`
	Chain  string   `yaml:"chain"`
	Table  string   `yaml:"table"`
}
