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

var clusterManagerCmd = APIEndpoint{
	Path: "cluster-manager",

	Get:    APIEndpointAction{Handler: clusterManagerGet, AccessHandler: allowPermission(entity.TypeServer, auth.EntitlementAdmin)},
	Post:   APIEndpointAction{Handler: clusterManagerPost, AccessHandler: allowPermission(entity.TypeServer, auth.EntitlementAdmin)},
	Delete: APIEndpointAction{Handler: clusterManagerDelete, AccessHandler: allowPermission(entity.TypeServer, auth.EntitlementAdmin)},
}

// swagger:operation GET /1.0/cluster-manager
//
//	Get cluster manager configuration
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
func clusterManagerGet(d *Daemon, r *http.Request) response.Response {
	s := d.State()

	addresses, serverCert := s.GlobalConfig.ClusterManagerServer()

	if serverCert == "" {
		return response.SyncResponse(true, api.ClusterManager{})
	}

	certInfo, err := shared.KeyPairAndCA(s.OS.VarDir, "cluster-manager", shared.CertServer, false)
	if err != nil {
		return response.InternalError(err)
	}

	resp := api.ClusterManager{
		ClusterManagerAddresses: addresses,
		LocalCertFingerprint:    certInfo.Fingerprint(),
		ServerCertFingerprint:   serverCert,
	}

	return response.SyncResponse(true, resp)
}

// swagger:operation POST /1.0/cluster-manager token
//
//	Configure cluster manager
//
//	Join a remote cluster manager with a token.
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
//	      $ref: "#/definitions/ClusterManagerPost"
//	responses:
//	  "200":
//	    $ref: "#/responses/EmptySyncResponse"
//	  "400":
//	    $ref: "#/responses/BadRequest"
//	  "403":
//	    $ref: "#/responses/Forbidden"
//	  "500":
//	    $ref: "#/responses/InternalServerError"
func clusterManagerPost(d *Daemon, r *http.Request) response.Response {
	s := d.State()

	args := api.ClusterManagerPost{}
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

	clusterManagerAddresses := strings.Join(joinToken.Addresses, ",")
	clusterManagerFingerprint := joinToken.Fingerprint
	updateConfig(d, r, clusterManagerAddresses, clusterManagerFingerprint)

	err = doPostJoinClusterManager(s, joinToken)
	if err != nil {
		return response.InternalError(err)
	}

	return response.SyncResponse(true, nil)
}

func doPostJoinClusterManager(s *state.State, joinToken *api.ClusterMemberJoinToken) error {
	client, publicKey := NewClusterManagerClient(s, joinToken.Fingerprint)

	payload := ClusterManagerPostCluster{
		ClusterName:        joinToken.ServerName,
		ClusterCertificate: publicKey,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := "https://" + joinToken.Addresses[0] + "/1.0/remote-clusters" // todo we should retry with the other addresses if this one fails
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, []byte(joinToken.Secret))
	mac.Write(reqBody)
	req.Header.Set("X-CLUSTER-SIGNATURE", base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to register in cluster manager: %s", resp.Status)
	}

	return nil
}

func updateConfig(d *Daemon, r *http.Request, addresses string, cert string) {
	putConfig := api.ServerPut{
		Config: map[string]any{
			"cluster-manager.addresses": addresses,
			"cluster-manager.cert":      cert,
		},
	}

	doAPI10Update(d, r, putConfig, true)
}

type ClusterManagerPostCluster struct {
	ClusterName        string `json:"cluster_name" yaml:"cluster_name"`
	ClusterCertificate string `json:"cluster_certificate" yaml:"cluster_certificate"`
}

// NewClusterManagerClient returns a cluster manager client.
func NewClusterManagerClient(s *state.State, serverFingerPrint string) (*http.Client, string) {
	client := &http.Client{}

	certInfo, err := shared.KeyPairAndCA(s.OS.VarDir, "cluster-manager", shared.CertServer, false)
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

// swagger:operation DELETE /1.0/cluster-manager
//
//	Delete cluster manager configuration
//
//	Remove this cluster from cluster manager
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
func clusterManagerDelete(d *Daemon, r *http.Request) response.Response {
	s := d.State()

	updateConfig(d, r, "", "")
	certFilename := filepath.Join(s.OS.VarDir, "cluster-manager.crt")
	keyFilename := filepath.Join(s.OS.VarDir, "cluster-manager.key")
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

type StatusDistribution struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

type ClusterManagerStatusPost struct {
	CPUTotalCount     int64                `json:"cpu_total_count"`
	CPULoad1          string               `json:"cpu_load_1"`
	CPULoad5          string               `json:"cpu_load_5"`
	CPULoad15         string               `json:"cpu_load_15"`
	MemoryTotalAmount int64                `json:"memory_total_amount"`
	MemoryUsage       int64                `json:"memory_usage"`
	DiskTotalSize     int64                `json:"disk_total_size"`
	DiskUsage         int64                `json:"disk_usage"`
	MemberStatuses    []StatusDistribution `json:"member_statuses"`
	InstanceStatuses  []StatusDistribution `json:"instance_status"`
}

func sendClusterManagerStatusMessage(ctx context.Context, s *state.State) {
	logger.Debug("Running sendClusterManagerStatusMessage")

	// Get the cluster manager addresses
	addresses, serverCert := s.GlobalConfig.ClusterManagerServer()

	if len(addresses) == 0 {
		logger.Debug("No cluster manager address configured")
		return
	}

	if serverCert == "" {
		logger.Debug("No cluster manager certificate configured")
		return
	}

	client, _ := NewClusterManagerClient(s, serverCert)

	payload := ClusterManagerStatusPost{}

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

	logger.Debug("Sending status message to cluster manager", logger.Ctx{"reqBody": string(reqBody)})

	url := "https://" + addresses[0] + "/1.0/remote-clusters/status" // todo we should retry with the other addresses if this one fails
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		logger.Error("Failed to create request", logger.Ctx{"err": err})
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to send status message to cluster manager", logger.Ctx{"err": err})
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.Error("Invalid status code received from cluster manager", logger.Ctx{"status": resp.Status})
		return
	}

	logger.Debug("Done sending status message to cluster manager")
}

func enrichInstanceMetrics(ctx context.Context, s *state.State, result *ClusterManagerStatusPost) error {
	instanceFrequencies := make(map[string]int64)
	err := s.DB.Cluster.Transaction(ctx, func(ctx context.Context, tx *db.ClusterTx) error {
		return tx.InstanceList(ctx, func(dbInst db.InstanceArgs, p api.Project) error {
			inst, err := instance.Load(s, dbInst, p)
			if err != nil {
				return fmt.Errorf("failed loading instances for cluster manager status update task: %w", err)
			}
			instanceFrequencies[inst.State()]++
			return nil
		})
	})
	if err != nil {
		return err
	}

	for status, count := range instanceFrequencies {
		result.InstanceStatuses = append(result.InstanceStatuses, StatusDistribution{
			Status: status,
			Count:  count,
		})
	}

	return err
}

func enrichClusterMemberMetrics(ctx context.Context, s *state.State, result *ClusterManagerStatusPost) error {
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

	var cpuLoad1 float64
	var cpuLoad5 float64
	var cpuLoad15 float64
	statusFrequencies := make(map[string]int64)
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

		result.MemoryTotalAmount += int64(memberState.SysInfo.TotalRAM)
		result.MemoryUsage += int64(memberState.SysInfo.TotalRAM - memberState.SysInfo.FreeRAM)

		result.CPUTotalCount += int64(memberState.SysInfo.NumCpu)
		cpuLoad1 += memberState.SysInfo.LoadAverages[0]
		cpuLoad5 += memberState.SysInfo.LoadAverages[1]
		cpuLoad15 += memberState.SysInfo.LoadAverages[2]

		for _, poolsState := range memberState.StoragePools {
			result.DiskTotalSize += int64(poolsState.Space.Total)
			result.DiskUsage += int64(poolsState.Space.Used)
		}
	}

	for status, count := range statusFrequencies {
		result.MemberStatuses = append(result.MemberStatuses, StatusDistribution{
			Status: status,
			Count:  count,
		})
	}

	if result.CPUTotalCount > 0 {
		result.CPULoad1 = fmt.Sprintf("%.2f", cpuLoad1/float64(result.CPUTotalCount))
		result.CPULoad5 = fmt.Sprintf("%.2f", cpuLoad5/float64(result.CPUTotalCount))
		result.CPULoad15 = fmt.Sprintf("%.2f", cpuLoad15/float64(result.CPUTotalCount))
	} else {
		result.CPULoad1 = fmt.Sprintf("%.2f", cpuLoad1)
		result.CPULoad5 = fmt.Sprintf("%.2f", cpuLoad5)
		result.CPULoad15 = fmt.Sprintf("%.2f", cpuLoad15)
	}

	return nil
}

func sendClusterManagerStatusMessageTask(d *Daemon) (task.Func, task.Schedule) {
	f := func(ctx context.Context) {
		sendClusterManagerStatusMessage(ctx, d.State())
	}

	return f, task.Every(time.Minute)
}
