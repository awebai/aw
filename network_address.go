package aweb

import "strings"

// NetworkAddress represents either a cross-org network address (org-slug/alias)
// or a plain intra-project alias.
type NetworkAddress struct {
	OrgSlug   string
	Alias     string
	IsNetwork bool
}

// ParseNetworkAddress parses a target string into a NetworkAddress.
// If the string contains a '/', it is treated as a network address (org-slug/alias).
// Otherwise it is a plain intra-project alias.
func ParseNetworkAddress(target string) NetworkAddress {
	target = strings.TrimSpace(target)
	if target == "" {
		return NetworkAddress{}
	}

	idx := strings.IndexByte(target, '/')
	if idx < 0 {
		return NetworkAddress{Alias: target}
	}

	return NetworkAddress{
		OrgSlug:   target[:idx],
		Alias:     target[idx+1:],
		IsNetwork: true,
	}
}

// String returns the canonical string form of the address.
func (a NetworkAddress) String() string {
	if a.IsNetwork {
		return a.OrgSlug + "/" + a.Alias
	}
	return a.Alias
}
