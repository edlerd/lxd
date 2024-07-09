package api

// swagger:model
type SiteManagerPost struct {
	Token string `json:"token" yaml:"token"`
}

// SiteManager represents the LXD site manager configuration
//
// swagger:model
type SiteManager struct {
	// The profile name
	// Example: 203.0.113.1:443
	SiteManagerAddresses []string `json:"addresses" yaml:"addresses"`

	// Fingerprint of this cluster towards the site manager
	// Example: 90fedb21cda5ac6a45a878c151e6ac8fe16b4b723e44669fd113e4ea07597d83
	LocalCertFingerprint string `json:"local_cert_fingerprint" yaml:"local_cert_fingerprint"`

	// Fingerprint of the site manager server certificate
	// Example: 90fedb21cda5ac6a45a878c151e6ac8fe16b4b723e44669fd113e4ea07597d83
	ServerCertFingerprint string `json:"server_cert_fingerprint" yaml:"server_cert_fingerprint"`
}
