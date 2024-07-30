package api

// swagger:model
type ClusterManagerPost struct {
	Token string `json:"token" yaml:"token"`
}

// ClusterManager represents the LXD cluster manager configuration
//
// swagger:model
type ClusterManager struct {
	// The profile name
	// Example: 203.0.113.1:443
	ClusterManagerAddresses []string `json:"addresses" yaml:"addresses"`

	// Fingerprint of this cluster towards the cluster manager
	// Example: 90fedb21cda5ac6a45a878c151e6ac8fe16b4b723e44669fd113e4ea07597d83
	LocalCertFingerprint string `json:"local_cert_fingerprint" yaml:"local_cert_fingerprint"`

	// Fingerprint of the cluster manager server certificate
	// Example: 90fedb21cda5ac6a45a878c151e6ac8fe16b4b723e44669fd113e4ea07597d83
	ServerCertFingerprint string `json:"server_cert_fingerprint" yaml:"server_cert_fingerprint"`
}
