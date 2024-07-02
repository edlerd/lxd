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
