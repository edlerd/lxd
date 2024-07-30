package lxd

import "github.com/canonical/lxd/shared/api"

// PostClusterManager sets cluster manager configuration.
func (r *ProtocolLXD) PostClusterManager(args api.ClusterManagerPost) error {
	err := r.CheckExtension("cluster_manager")
	if err != nil {
		return err
	}

	// Send the request.
	_, _, err = r.query("POST", "/cluster-manager", args, "")
	if err != nil {
		return err
	}

	return nil
}

// GetClusterManager displays cluster manager configuration.
func (r *ProtocolLXD) GetClusterManager() (configuration *api.ClusterManager, err error) {
	err = r.CheckExtension("cluster_manager")
	if err != nil {
		return nil, err
	}

	// Send the request.
	response, _, err := r.query("GET", "/cluster-manager", nil, "")
	if err != nil {
		return nil, err
	}

	var result api.ClusterManager

	err = response.MetadataAsStruct(&result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteClusterManager sets cluster manager configuration.
func (r *ProtocolLXD) DeleteClusterManager() error {
	err := r.CheckExtension("cluster_manager")
	if err != nil {
		return err
	}

	// Send the request.
	_, _, err = r.query("DELETE", "/cluster-manager", nil, "")
	if err != nil {
		return err
	}

	return nil
}
