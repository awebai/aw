package awid

// Account holds the protocol identity fields for an agent.
// Coordination-layer extensions (e.g. DefaultProject) are added by
// the awconfig package via embedding.
type Account struct {
	Server        string `yaml:"server,omitempty"`
	APIKey        string `yaml:"api_key,omitempty"`
	AgentID       string `yaml:"agent_id,omitempty"`
	AgentAlias    string `yaml:"agent_alias,omitempty"`
	Email         string `yaml:"email,omitempty"`
	NamespaceSlug string `yaml:"namespace_slug,omitempty"`
	DID           string `yaml:"did,omitempty"`
	StableID      string `yaml:"stable_id,omitempty"`
	SigningKey    string `yaml:"signing_key,omitempty"`
	Custody       string `yaml:"custody,omitempty"`
	Lifetime      string `yaml:"lifetime,omitempty"`
}
