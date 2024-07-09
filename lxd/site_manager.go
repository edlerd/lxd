package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/canonical/lxd/lxd/auth"
	"github.com/canonical/lxd/lxd/cluster"
	"github.com/canonical/lxd/lxd/db"
	"github.com/canonical/lxd/lxd/instance"
	"github.com/canonical/lxd/lxd/response"
	"github.com/canonical/lxd/lxd/state"
	"github.com/canonical/lxd/lxd/task"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/entity"
	"github.com/canonical/lxd/shared/logger"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var siteManagerCmd = APIEndpoint{
	Path: "site-manager",

	Get:    APIEndpointAction{Handler: siteManagerGet, AccessHandler: allowPermission(entity.TypeServer, auth.EntitlementAdmin)},
	Post:   APIEndpointAction{Handler: siteManagerPost, AccessHandler: allowPermission(entity.TypeServer, auth.EntitlementAdmin)},
	Delete: APIEndpointAction{Handler: siteManagerDelete, AccessHandler: allowPermission(entity.TypeServer, auth.EntitlementAdmin)},
}

// swagger:operation GET /1.0/site-manager
//
//	Get site manager configuration
//
//	---
//	consumes:
//	  - application/json
//	produces:
//	  - application/json
//	responses:
//	  "200":
//	    $ref: "#/responses/EmptySyncResponse"
//	  "400":
//	    $ref: "#/responses/BadRequest"
//	  "403":
//	    $ref: "#/responses/Forbidden"
//	  "500":
//	    $ref: "#/responses/InternalServerError"
func siteManagerGet(d *Daemon, r *http.Request) response.Response {
	s := d.State()

	addresses, serverCert := s.GlobalConfig.SiteManagerServer()

	if serverCert == "" {
		return response.SyncResponse(true, api.SiteManager{})
	}

	certInfo, err := shared.KeyPairAndCA(s.OS.VarDir, "site-manager", shared.CertServer, false)
	if err != nil {
		return response.InternalError(err)
	}

	resp := api.SiteManager{
		SiteManagerAddresses:  addresses,
		LocalCertFingerprint:  certInfo.Fingerprint(),
		ServerCertFingerprint: serverCert,
	}

	return response.SyncResponse(true, resp)
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
		return response.BadRequest(fmt.Errorf("no token provided"))
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
	client, publicKey := NewSiteManagerClient(s, joinToken.Fingerprint)

	payload := SiteManagerPostSite{
		SiteName:        joinToken.ServerName,
		SiteCertificate: publicKey,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := "https://" + joinToken.Addresses[0] + "/1.0/sites" // todo we should retry with the other addresses if this one fails
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
func NewSiteManagerClient(s *state.State, serverFingerPrint string) (*http.Client, string) {
	client := &http.Client{}

	certInfo, err := shared.KeyPairAndCA(s.OS.VarDir, "site-manager", shared.CertServer, false)
	if err != nil {
		return nil, ""
	}

	cert := certInfo.KeyPair()
	publicKey := string(certInfo.PublicKey())

	// todo: distribute the certificate among all cluster members of lxd

	tlsConfig := shared.InitTLSConfig()

	tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		// GetClientCertificate is called if not nil instead of performing the default selection of an appropriate
		// certificate from the `Certificates` list. We only have one-key pair to send, and we always want to send it
		// because this is what uniquely identifies the caller to the server.
		return &cert, nil
	}

	// the server certificate is not signed by a CA, so we need to skip verification
	// we do validate it by checking the fingerprint with VerifyPeerCertificate
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Extract the certificate
		if len(rawCerts) == 0 {
			return fmt.Errorf("no server certificate provided")
		}
		cert := rawCerts[0]

		// Calculate the fingerprint
		h := sha256.New()
		h.Write(cert)
		actualFingerprint := hex.EncodeToString(h.Sum(nil))

		// Compare with the expected fingerprint
		if strings.ToLower(actualFingerprint) != strings.ToLower(serverFingerPrint) {
			return fmt.Errorf("unexpected certificate fingerprint: %s", actualFingerprint)
		}

		return nil
	}

	client.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return client, publicKey
}

// swagger:operation DELETE /1.0/site-manager
//
//	Delete site manager configuration
//
//	Remove this cluster from site manager
//
//	---
//	produces:
//	  - application/json
//	responses:
//	  "200":
//	    $ref: "#/responses/EmptySyncResponse"
//	  "400":
//	    $ref: "#/responses/BadRequest"
//	  "403":
//	    $ref: "#/responses/Forbidden"
//	  "500":
//	    $ref: "#/responses/InternalServerError"
func siteManagerDelete(d *Daemon, r *http.Request) response.Response {
	s := d.State()

	updateConfig(d, r, "", "")
	certFilename := filepath.Join(s.OS.VarDir, "site-manager.crt")
	keyFilename := filepath.Join(s.OS.VarDir, "site-manager.key")
	if shared.PathExists(certFilename) {
		err := os.Remove(certFilename)
		if err != nil {
			return nil
		}
	}
	if shared.PathExists(keyFilename) {
		err := os.Remove(keyFilename)
		if err != nil {
			return nil
		}
	}
	return response.SyncResponse(true, nil)
}

type MemberStatus struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

type InstanceStatus struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

type SiteManagerStatusPost struct {
	CpuTotalCount     int              `json:"cpu_total_count"`
	CpuUsage          string           `json:"cpu_usage"`
	MemoryTotalAmount int              `json:"memory_total_amount"`
	MemoryUsage       int              `json:"memory_usage"`
	DiskTotalSize     int              `json:"disk_total_size"`
	DiskUsage         int              `json:"disk_usage"`
	MemberStatuses    []MemberStatus   `json:"member_statuses"`
	InstanceStatuses  []InstanceStatus `json:"instance_status"`
}

func sendSiteManagerStatusMessage(ctx context.Context, s *state.State) {
	logger.Debug("Running sendSiteManagerStatusMessage")

	// Get the site manager addresses
	addresses, serverCert := s.GlobalConfig.SiteManagerServer()

	if len(addresses) == 0 {
		logger.Debug("No site manager address configured")
		return
	}

	if serverCert == "" {
		logger.Debug("No site manager certificate configured")
		return
	}

	client, _ := NewSiteManagerClient(s, serverCert)

	payload := SiteManagerStatusPost{}

	err := enrichClusterMemberMetrics(ctx, s, &payload)
	if err != nil {
		logger.Error("Failed to enrich cluster member metrics", logger.Ctx{"err": err})
		return
	}

	err = enrichInstanceMetrics(ctx, s, &payload)
	if err != nil {
		logger.Error("Failed to enrich instance metrics", logger.Ctx{"err": err})
		return
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal status message", logger.Ctx{"err": err})
		return
	}

	logger.Debug("Sending status message to site manager", logger.Ctx{"reqBody": string(reqBody)})

	url := "https://" + addresses[0] + "/1.0/sites/status" // todo we should retry with the other addresses if this one fails
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		logger.Error("Failed to create request", logger.Ctx{"err": err})
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to send status message to site manager", logger.Ctx{"err": err})
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.Error("Invalid status code received from site manager", logger.Ctx{"status": resp.Status})
		return
	}

	logger.Debug("Done sending status message to site manager")
}

func enrichInstanceMetrics(ctx context.Context, s *state.State, result *SiteManagerStatusPost) error {
	instanceFrequencies := make(map[string]int)
	err := s.DB.Cluster.Transaction(ctx, func(ctx context.Context, tx *db.ClusterTx) error {
		return tx.InstanceList(ctx, func(dbInst db.InstanceArgs, p api.Project) error {
			inst, err := instance.Load(s, dbInst, p)
			if err != nil {
				return fmt.Errorf("failed loading instances for site manager status update task: %w", err)
			}
			instanceFrequencies[inst.State()]++
			return nil
		})
	})
	if err != nil {
		return err
	}

	for status, count := range instanceFrequencies {
		result.InstanceStatuses = append(result.InstanceStatuses, InstanceStatus{
			Status: status,
			Count:  count,
		})
	}

	return err
}

func enrichClusterMemberMetrics(ctx context.Context, s *state.State, result *SiteManagerStatusPost) error {
	var members []db.NodeInfo
	var err error

	if s.ServerClustered {
		err := s.DB.Cluster.Transaction(ctx, func(ctx context.Context, tx *db.ClusterTx) error {
			members, err = tx.GetNodes(ctx)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		members = append(members, db.NodeInfo{
			Name: "single node",
		})
	}

	var cpuUsageSum float64
	statusFrequencies := make(map[string]int)
	for i := range members {
		member := members[i]

		var status string
		switch member.State {
		case db.ClusterMemberStateCreated:
			status = "Created"
		case db.ClusterMemberStatePending:
			status = "Pending"
		case db.ClusterMemberStateEvacuated:
			status = "Evacuated"
		default:
			status = "Online"
		}

		if member.IsOffline(s.GlobalConfig.OfflineThreshold()) {
			status = "Offline"
		}

		// in case of a single non-clustered node, we consider it online
		if !s.ServerClustered {
			status = "Online"
		}

		statusFrequencies[status]++
		memberState, err := cluster.MemberState(ctx, s, member.Name)
		if err != nil {
			return err
		}

		result.MemoryTotalAmount += int(memberState.SysInfo.TotalRAM)
		result.MemoryUsage += int(memberState.SysInfo.TotalRAM - memberState.SysInfo.FreeRAM)

		result.CpuTotalCount += memberState.SysInfo.NumCpu
		cpuUsageSum += memberState.SysInfo.LoadAverages[0]

		for _, poolsState := range memberState.StoragePools {
			result.DiskTotalSize += int(poolsState.Space.Total)
			result.DiskUsage += int(poolsState.Space.Used)
		}
	}

	for status, count := range statusFrequencies {
		result.MemberStatuses = append(result.MemberStatuses, MemberStatus{
			Status: status,
			Count:  count,
		})
	}

	if result.CpuTotalCount > 0 {
		result.CpuUsage = fmt.Sprintf("%.2f", cpuUsageSum/float64(result.CpuTotalCount))
	} else {
		result.CpuUsage = fmt.Sprintf("%.2f", cpuUsageSum)
	}

	return nil
}

func sendSiteManagerStatusMessageTask(d *Daemon) (task.Func, task.Schedule) {
	f := func(ctx context.Context) {
		sendSiteManagerStatusMessage(ctx, d.State())
	}

	return f, task.Every(time.Minute)
}
