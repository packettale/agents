package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/packettale/agents/service/netenv"
	"io"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/packettale/agents/service/netquery/orm"
)

var localApplicationID = regexp.MustCompile(`^local/[A-Za-z0-9_-]{1,200}$`)

type publicAddress struct {
	Address string `json:"address"`
	Source  string `json:"source"`
}

type applicationIdentity struct {
	ProfileID string `json:"profile_id" sqlite:"profile_id"`
	Name      string `json:"name" sqlite:"name"`
	Path      string `json:"path" sqlite:"path"`
	Icon      []byte `json:"icon"`
}

// flushApplicationCatalogue samples the small, current in-memory connection
// store. It never scans retained history and never runs on the packet path.
func (c *Client) flushApplicationCatalogue(ctx context.Context, config Config) error {
	if !c.applicationCatalogueEnabled.Load() || c.store == nil {
		return nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	state, err := readIdentity(c.dataDir)
	if err != nil {
		return err
	}
	if state.Credential == "" {
		return fmt.Errorf("device is not enrolled")
	}
	interfaces, err := netenv.AssignedInterfaceAddresses()
	if err != nil {
		return fmt.Errorf("read interface addresses: %w", err)
	}
	localAddress := catalogueLocalAddress(interfaces, c.connectionLocalIP.Load())
	publicIPs := []publicAddress{}
	for address, source := range netenv.KnownPublicAddresses() {
		publicIPs = append(publicIPs, publicAddress{address, source})
	}
	sort.Slice(publicIPs, func(i, j int) bool { return publicIPs[i].Address < publicIPs[j].Address })
	if len(publicIPs) > 16 {
		publicIPs = publicIPs[:16]
	}
	after := ""
	for {
		var rows []applicationIdentity
		err := c.store.Execute(queryCtx, `WITH observed AS (
            SELECT profile, profile_name, path,
                ROW_NUMBER() OVER (PARTITION BY profile ORDER BY started DESC,id DESC) AS position
            FROM main.connections WHERE internal = 0 AND profile LIKE 'local/%' AND profile > :after
        ) SELECT profile AS profile_id, profile_name AS name, substr(COALESCE(path,''),1,4096) AS path FROM observed
          WHERE position = 1 ORDER BY profile LIMIT 20`,
			orm.WithNamedArgs(map[string]interface{}{":after": after}), orm.WithResult(&rows))
		if err != nil {
			return fmt.Errorf("query observed application profiles: %w", err)
		}
		if len(rows) == 0 && after != "" {
			return nil
		}
		applications := make([]applicationIdentity, 0, len(rows))
		for _, row := range rows {
			if localApplicationID.MatchString(row.ProfileID) {
				row.Name = boundedLabel(row.Name)
				row.Icon = applicationIcon(row.ProfileID)
				applications = append(applications, row)
			}
		}
		if len(applications) > 0 || after == "" {
			body, err := json.Marshal(struct {
				Applications []applicationIdentity     `json:"applications"`
				PublicIPs    []publicAddress           `json:"public_ips"`
				Interfaces   []netenv.InterfaceAddress `json:"interface_addresses"`
				LocalAddress string                    `json:"local_address"`
			}{applications, publicIPs, interfaces, localAddress})
			if err != nil {
				return err
			}
			request, err := http.NewRequestWithContext(queryCtx, http.MethodPost, config.ServerURL+"/api/v1/device/applications/", bytes.NewReader(body))
			if err != nil {
				return err
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+state.Credential)
			response, err := c.httpClient.Do(request)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode != http.StatusAccepted {
				return fmt.Errorf("application catalogue rejected with HTTP %d", response.StatusCode)
			}
		}
		if len(rows) < 20 {
			return nil
		}
		after = rows[len(rows)-1].ProfileID
	}
}

// A connected socket identifies the source actually used to reach the portal.
// Do not report a stale source after its interface disappears, or guess one
// from interface enumeration order. Split-tunnel apps may use other routes.
func catalogueLocalAddress(interfaces []netenv.InterfaceAddress, source *string) string {
	if source != nil {
		for _, row := range interfaces {
			if row.Address == *source {
				return row.Address
			}
		}
	}
	return ""
}
