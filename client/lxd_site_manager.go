package lxd

import "github.com/canonical/lxd/shared/api"

// PostSiteManager sets site manager configuration.
func (r *ProtocolLXD) PostSiteManager(args api.SiteManagerPost) error {
	err := r.CheckExtension("site_manager")
	if err != nil {
		return err
	}

	// Send the request.
	_, _, err = r.query("POST", "/site-manager", args, "")
	if err != nil {
		return err
	}

	return nil
}

// GetSiteManager displays site manager configuration.
func (r *ProtocolLXD) GetSiteManager() (configuration *api.SiteManager, err error) {
	err = r.CheckExtension("site_manager")
	if err != nil {
		return nil, err
	}

	// Send the request.
	response, _, err := r.query("GET", "/site-manager", nil, "")
	if err != nil {
		return nil, err
	}

	var result api.SiteManager

	err = response.MetadataAsStruct(&result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteSiteManager sets site manager configuration.
func (r *ProtocolLXD) DeleteSiteManager() error {
	err := r.CheckExtension("site_manager")
	if err != nil {
		return err
	}

	// Send the request.
	_, _, err = r.query("DELETE", "/site-manager", nil, "")
	if err != nil {
		return err
	}

	return nil
}
