package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/canonical/lxd/lxd/auth"
	"github.com/canonical/lxd/lxd/response"
	"github.com/canonical/lxd/lxd/state"
	"github.com/canonical/lxd/lxd/util"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/entity"
	"net/http"
	"strings"
)

var siteManagerCmd = APIEndpoint{
	Path: "site-manager",

	Post: APIEndpointAction{Handler: siteManagerPost, AccessHandler: allowPermission(entity.TypeProject, auth.EntitlementCanCreateProfiles)},
}

// swagger:operation POST /1.0/site-manager token
//
//	Configure site manager
//
//	Join a remote site manager with a token.
//
//	---
//	consumes:
//	  - application/json
//	produces:
//	  - application/json
//	parameters:
//	  - in: body
//	    token: string
//	    required: true
//	    schema:
//	      $ref: "#/definitions/SiteManagerPost"
//	responses:
//	  "200":
//	    $ref: "#/responses/EmptySyncResponse"
//	  "400":
//	    $ref: "#/responses/BadRequest"
//	  "403":
//	    $ref: "#/responses/Forbidden"
//	  "500":
//	    $ref: "#/responses/InternalServerError"
func siteManagerPost(d *Daemon, r *http.Request) response.Response {
	s := d.State()

	args := api.SiteManagerPost{}
	err := json.NewDecoder(r.Body).Decode(&args)
	if err != nil {
		return response.BadRequest(err)
	}

	if args.Token == "" {
		return response.BadRequest(fmt.Errorf("No token provided"))
	}

	joinToken, err := shared.JoinTokenDecode(args.Token)
	if err != nil {
		return response.BadRequest(err)
	}

	siteManagerAddresses := strings.Join(joinToken.Addresses, ",")
	siteManagerFingerprint := joinToken.Fingerprint
	updateConfig(d, r, siteManagerAddresses, siteManagerFingerprint)

	err = doPostJoinSiteManager(s, joinToken)
	if err != nil {
		return response.InternalError(err)
	}

	return response.SyncResponse(true, nil)
}

func doPostJoinSiteManager(s *state.State, joinToken *api.ClusterMemberJoinToken) error {
	client, siteCert := NewSiteManagerClient(s)

	payload := SiteManagerPostSite{
		SiteName:        joinToken.ServerName,
		SiteCertificate: siteCert,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := "https://" + joinToken.Addresses[0] + "/1.0/sites"
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, []byte(joinToken.Secret))
	mac.Write(reqBody)
	req.Header.Set("X-SITE-SIGNATURE", base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to register in site manager: %s", resp.Status)
	}

	return nil
}

func updateConfig(d *Daemon, r *http.Request, addresses string, cert string) {
	putConfig := api.ServerPut{
		Config: map[string]any{
			"site-manager.addresses": addresses,
			"site-manager.cert":      cert,
		},
	}

	doAPI10Update(d, r, putConfig, true)
}

type SiteManagerPostSite struct {
	SiteName        string `json:"site_name" yaml:"site_name"`
	SiteCertificate string `json:"site_certificate" yaml:"site_certificate"`
}

// NewSiteManagerClient returns a site manager client.
func NewSiteManagerClient(s *state.State) (*http.Client, string) {
	client := &http.Client{}

	certInfo, err := shared.KeyPairAndCA(s.OS.VarDir, "site-manager", shared.CertServer, false)
	if err != nil {
		return nil, ""
	}

	// todo: distribute the certificate among the cluster members of lxd

	tlsConfig := util.ServerTLSConfig(certInfo)

	client.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return client, certInfo.Fingerprint()
}
