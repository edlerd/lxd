package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/canonical/lxd/lxd/auth"
	"github.com/canonical/lxd/lxd/cluster"
	"github.com/canonical/lxd/lxd/db"
	"github.com/canonical/lxd/lxd/instance"
	"github.com/canonical/lxd/lxd/response"
	"github.com/canonical/lxd/lxd/state"
	"github.com/canonical/lxd/lxd/task"
	"github.com/canonical/lxd/lxd/util"
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

	Post:   APIEndpointAction{Handler: siteManagerPost, AccessHandler: allowPermission(entity.TypeServer, auth.EntitlementAdmin)},
	Delete: APIEndpointAction{Handler: siteManagerDelete, AccessHandler: allowPermission(entity.TypeServer, auth.EntitlementAdmin)},
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
		os.Remove(certFilename)
	}
	if shared.PathExists(keyFilename) {
		os.Remove(keyFilename)
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
	SiteCertificate   string           `json:"site_certificate"`
	CpuTotalCount     int              `json:"cpu_total_count"`
	CpuUsage          int              `json:"cpu_usage"`
	MemoryTotalAmount int              `json:"memory_total_amount"`
	MemoryUsage       int              `json:"memory_usage"`
	DiskTotalSize     int              `json:"disk_total_size"`
	DiskUsage         int              `json:"disk_usage"`
	MemberStatuses    []MemberStatus   `json:"member_statuses"`
	InstanceStatuses  []InstanceStatus `json:"instance_status"`
}

func sendSiteManagerStatusMessage(ctx context.Context, s *state.State) {
	logger.Warn("Running sendSiteManagerStatusMessage")

	// Get the site manager addresses
	addresses, cert := s.GlobalConfig.SiteManagerServer()

	if len(addresses) == 0 {
		logger.Warn("No site manager address configured")
		return
	}

	if cert == "" {
		logger.Warn("No site manager certificate configured")
		return
	}

	client, siteCert := NewSiteManagerClient(s)

	var memberStatusFrequencies []MemberStatus
	var cpuTotalCount int
	var cpuUsage int
	var memoryTotalAmount int
	var memoryFree int
	var diskTotalSize int
	var diskUsage int
	err := s.DB.Cluster.Transaction(ctx, func(ctx context.Context, tx *db.ClusterTx) error {
		members, err := tx.GetNodes(ctx)
		if err != nil {
			return err
		}

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
			// in case of a single member cluster, we are on the node, and it is not offline
			if len(members) > 1 && member.IsOffline(s.GlobalConfig.OfflineThreshold()) {
				status = "Offline"
			}

			statusFrequencies[status]++
			memberState, err := cluster.MemberState(ctx, s, member.Name)
			if err != nil {
				return err
			}

			// todo: below metrics need to be summed over all members, not just the current member
			memoryTotalAmount += int(memberState.SysInfo.TotalRAM)
			memoryFree += int(memberState.SysInfo.FreeRAM)

			cpuTotalCount += 0                                         // todo: this should be the sum of all members
			cpuUsage += int(memberState.SysInfo.LoadAverages[0] * 100) // todo: this is not the correct way to calculate cpu usage

			for _, poolsState := range memberState.StoragePools {
				diskTotalSize += int(poolsState.Space.Total)
				diskUsage += int(poolsState.Space.Used)
			}
		}

		for status, count := range statusFrequencies {
			memberStatusFrequencies = append(memberStatusFrequencies, MemberStatus{
				Status: status,
				Count:  count,
			})
		}

		return nil
	})
	if err != nil {
		logger.Error("Failed getting cluster member statuses", logger.Ctx{"err": err})
		return
	}

	var instanceStatuses []InstanceStatus
	instanceFrequencies := make(map[string]int)
	err = s.DB.Cluster.Transaction(ctx, func(ctx context.Context, tx *db.ClusterTx) error {
		return tx.InstanceList(ctx, func(dbInst db.InstanceArgs, p api.Project) error {
			inst, err := instance.Load(s, dbInst, p)
			if err != nil {
				return fmt.Errorf("Failed loading instance %q (project %q) for snapshot task: %w", dbInst.Name, dbInst.Project, err)
			}
			instanceFrequencies[inst.State()]++
			return nil
		})
	})
	if err != nil {
		logger.Error("Failed getting instance status frequencies", logger.Ctx{"err": err})
		return
	}

	for status, count := range instanceFrequencies {
		instanceStatuses = append(instanceStatuses, InstanceStatus{
			Status: status,
			Count:  count,
		})
	}

	payload := SiteManagerStatusPost{
		SiteCertificate:   siteCert,
		CpuTotalCount:     cpuTotalCount,
		CpuUsage:          cpuUsage,
		MemoryTotalAmount: memoryTotalAmount,
		MemoryUsage:       memoryTotalAmount - memoryFree, // todo: ensure this calculation is correct
		DiskTotalSize:     diskTotalSize,
		DiskUsage:         diskUsage,
		MemberStatuses:    memberStatusFrequencies,
		InstanceStatuses:  instanceStatuses,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal status message", logger.Ctx{"err": err})
		return
	}

	logger.Warn("Sending status message to site manager")

	url := "http://" + addresses[0] + "/1.0/sites/status"
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
		logger.Error("Failed to send status message to site manager", logger.Ctx{"status": resp.Status})
		return
	}

	logger.Warn("Done sending status message to site manager")
}

func sendSiteManagerStatusMessageTask(d *Daemon) (task.Func, task.Schedule) {
	f := func(ctx context.Context) {
		sendSiteManagerStatusMessage(ctx, d.State())
	}

	return f, task.Every(time.Minute)
}
