package management

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/packettale/agents/service/netquery/orm"
)

const sqliteTime = "2006-01-02 15:04:05"

// Leave room for the management server's JSON Unicode escaping and whitespace
// within its 128 KiB relay limit. Larger results continue on the next page.
const maxDetailResponseBytes = 32 * 1024

const detailWhere = `strftime('%s', started)+0 >= :since AND strftime('%s', started)+0 < :until
	AND internal = 0
	AND (:app = '' OR profile_name = :app)
	AND (:profile = '' OR profile = :profile)
	AND (:country = '' OR (CASE WHEN country GLOB '[A-Z][A-Z]' THEN country ELSE '' END) = CASE WHEN :country='unknown' THEN '' ELSE :country END)
	AND (:host = '' OR (domain <> '' AND domain COLLATE NOCASE IN (:domain,:fqdn)) OR remote_ip = :ip)
	AND (:blocked = 0 OR verdict IN (3,4))`

type detailRequest struct {
	RequestID   string `json:"request_id"`
	Since       string `json:"since"`
	Until       string `json:"until"`
	Limit       int    `json:"limit"`
	App         string `json:"app"`
	Host        string `json:"host"`
	BlockedOnly bool   `json:"blocked_only"`
	Country     string `json:"country"`
	ProfileID   string `json:"profile_id"`
	Cursor      struct {
		Started string `json:"started"`
		ID      string `json:"id"`
	} `json:"cursor"`
}

type detailRecord struct {
	ExtraData      string   `json:"-" sqlite:"extra_data"`
	BlockedByLists []string `json:"blocked_by_lists"`
	ID             string   `json:"id" sqlite:"id"`
	Started        string   `json:"started" sqlite:"started"`
	Type           string   `json:"type" sqlite:"type"`
	App            string   `json:"app" sqlite:"app"`
	ProfileID      string   `json:"profile_id" sqlite:"profile_id"`
	Domain         string   `json:"domain" sqlite:"domain"`
	RemoteIP       string   `json:"remote_ip" sqlite:"remote_ip"`
	RemotePort     int64    `json:"remote_port" sqlite:"remote_port"`
	LocalIP        string   `json:"local_ip" sqlite:"local_ip"`
	LocalPort      int64    `json:"local_port" sqlite:"local_port"`
	Protocol       int64    `json:"protocol" sqlite:"protocol"`
	Direction      string   `json:"direction" sqlite:"direction"`
	Path           string   `json:"path" sqlite:"path"`
	Country        string   `json:"country" sqlite:"country"`
	ASN            int64    `json:"asn" sqlite:"asn"`
	ASOwner        string   `json:"as_owner" sqlite:"as_owner"`
	Ended          string   `json:"ended" sqlite:"ended"`
	Verdict        int64    `json:"verdict" sqlite:"verdict"`
	Reason         string   `json:"reason" sqlite:"reason"`
	BytesSent      int64    `json:"bytes_sent" sqlite:"bytes_sent"`
	BytesReceived  int64    `json:"bytes_received" sqlite:"bytes_received"`
}

type detailResponse struct {
	Total      *int64         `json:"total,omitempty"`
	Type       string         `json:"type"`
	RequestID  string         `json:"request_id"`
	Records    []detailRecord `json:"records"`
	NextCursor *struct {
		Started string `json:"started"`
		ID      string `json:"id"`
	} `json:"next_cursor"`
	Error string `json:"error,omitempty"`
}

func (c *Client) queryDetail(ctx context.Context, data []byte) detailResponse {
	response := detailResponse{Type: "query_result", Records: []detailRecord{}}
	var request detailRequest
	if err := json.Unmarshal(data, &request); err != nil {
		response.Error = "invalid query"
		return response
	}
	response.RequestID = request.RequestID
	if (request.ProfileID != "" && !localApplicationID.MatchString(request.ProfileID)) ||
		(request.Country != "" && request.Country != "unknown" &&
			(len(request.Country) != 2 || request.Country[0] < 'A' || request.Country[0] > 'Z' || request.Country[1] < 'A' || request.Country[1] > 'Z')) {
		response.Error = "invalid connection filter"
		return response
	}
	since, err1 := time.Parse(sqliteTime, request.Since)
	until, err2 := time.Parse(sqliteTime, request.Until)
	if err1 != nil || err2 != nil || !since.Before(until) || until.Sub(since) > 30*24*time.Hour ||
		request.Limit < 1 || request.Limit > 100 || len(request.App) > 255 || len(request.Host) > 255 ||
		len(request.Cursor.Started) > 32 || len(request.Cursor.ID) > 512 || len(request.RequestID) > 64 || c.store == nil {
		response.Error = "invalid query"
		return response
	}
	cursorEpoch := since.Unix() - 1
	if request.Cursor.Started != "" {
		cursorTime, err := time.Parse(sqliteTime, request.Cursor.Started)
		if err != nil {
			response.Error = "invalid cursor"
			return response
		}
		cursorEpoch = cursorTime.Unix()
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows := make([]detailRecord, 0)
	host := strings.TrimSpace(request.Host)
	if strings.HasSuffix(host, "..") {
		response.Error = "invalid destination"
		return response
	}
	domain := strings.TrimSuffix(strings.ToLower(host), ".")
	ip := host
	if address, err := netip.ParseAddr(host); err == nil {
		ip = address.Unmap().String()
	}
	args := map[string]interface{}{
		":profile": request.ProfileID, ":country": request.Country,
		":since": since.Unix(), ":until": until.Unix(), ":app": request.App,
		":host": host, ":domain": domain, ":fqdn": domain + ".", ":ip": ip, ":blocked": request.BlockedOnly,
	}
	rowArgs := maps.Clone(args)
	rowArgs[":cursor_epoch"], rowArgs[":cursor_id"], rowArgs[":limit"] = cursorEpoch, request.Cursor.ID, request.Limit+1
	err := c.store.Execute(queryCtx, `SELECT id, started, type, COALESCE(profile_name,'') AS app,
		COALESCE(profile,'') AS profile_id,
		COALESCE(domain,'') AS domain, COALESCE(NULLIF(remote_ip,'<nil>'),'') AS remote_ip,
		remote_port, verdict, bytes_sent, bytes_received,
		COALESCE(NULLIF(local_ip,'<nil>'),'') AS local_ip,local_port,ip_protocol AS protocol,
		COALESCE(direction,'') AS direction,substr(COALESCE(path,''),1,4096) AS path,
		CASE WHEN country GLOB '[A-Z][A-Z]' THEN country ELSE '' END AS country,asn,substr(COALESCE(as_owner,''),1,255) AS as_owner,
		COALESCE(ended,'') AS ended,
		substr(COALESCE(CAST(extra_data AS TEXT),''),1,16384) AS extra_data,
		CASE WHEN json_valid(CAST(extra_data AS TEXT)) THEN
			CASE WHEN json_type(CAST(extra_data AS TEXT),'$.reason.Msg') = 'text'
				THEN substr(json_extract(CAST(extra_data AS TEXT),'$.reason.Msg'),1,1024)
				ELSE '' END ELSE '' END AS reason
		FROM history.connections
		WHERE `+detailWhere+`
		AND (strftime('%s', started)+0 > :cursor_epoch OR (strftime('%s', started)+0 = :cursor_epoch AND id > :cursor_id))
		ORDER BY strftime('%s', started)+0, id LIMIT :limit`, orm.WithNamedArgs(rowArgs), orm.WithResult(&rows))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			response.Error = "local query timed out"
		} else {
			response.Error = "local query failed"
		}
		return response
	}
	// A slow or unavailable count must not discard an otherwise successful page.
	var totals []struct {
		Count int64 `sqlite:"count"`
	}
	if err := c.store.Execute(queryCtx, `SELECT COUNT(*) AS count FROM history.connections WHERE `+detailWhere, orm.WithNamedArgs(args), orm.WithResult(&totals)); err == nil && len(totals) == 1 && totals[0].Count >= int64(len(rows)) {
		response.Total = &totals[0].Count
	}
	hasMore := len(rows) > request.Limit
	if hasMore {
		rows = rows[:request.Limit]
	}
	for i := range rows {
		rows[i].BlockedByLists = detailLists(rows[i].ExtraData)
		rows[i].ExtraData = ""
		// SQLite's JSON functions may accept lone surrogates or invalid UTF-8.
		// Treat those optional explanations as malformed before JSON encoding
		// can replace their bytes and expand them beyond the transport bound.
		if !utf8.ValidString(rows[i].Reason) {
			rows[i].Reason = ""
			continue
		}
		for len(rows[i].Reason) > 1024 {
			_, size := utf8.DecodeLastRuneInString(rows[i].Reason)
			rows[i].Reason = rows[i].Reason[:len(rows[i].Reason)-size]
		}
	}
	response.Records = rows
	for len(response.Records) > 0 {
		if hasMore {
			last := response.Records[len(response.Records)-1]
			response.NextCursor = &struct {
				Started string `json:"started"`
				ID      string `json:"id"`
			}{Started: last.Started, ID: last.ID}
		}
		encoded, err := json.Marshal(response)
		if err == nil && len(encoded) <= maxDetailResponseBytes {
			return response
		}
		response.Records = response.Records[:len(response.Records)-1]
		hasMore = true
	}
	if len(rows) > 0 {
		response.NextCursor = nil
		response.Error = "local record exceeds response size limit"
	}
	return response
}

// Only recorded list identifiers leave the optional local metadata blob.
func detailLists(data string) []string {
	result := []string{}
	var extra struct {
		Lists []string `json:"blockedByLists"`
	}
	if json.Unmarshal([]byte(data), &extra) != nil {
		return result
	}
	seen := map[string]bool{}
	for _, value := range extra.Lists {
		if value != "" && len(value) <= 64 && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl) && !seen[value] {
			result = append(result, value)
			seen[value] = true
			if len(result) == 64 {
				break
			}
		}
	}
	return result
}
