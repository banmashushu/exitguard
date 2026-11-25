package subscription

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"exitguard/internal/model"
	"io"
	"strings"
	"time"
)

const MaxSubscriptions = 8
const DownloadDirect = "direct"
const DownloadActiveExitGuard = "active_exitguard"

func NormalizeDownloadRoute(route string) (string, error) {
	switch route {
	case "", DownloadDirect:
		return DownloadDirect, nil
	case DownloadActiveExitGuard:
		return route, nil
	default:
		return "", errors.New("订阅下载路线无效")
	}
}

var ErrStorage = errors.New("本机订阅库无法读取或更新；请检查文件权限和订阅内容")

type Record struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	SourceKind    string `json:"sourceKind"`
	SourceURL     string `json:"sourceURL"`
	UpdatedAt     string `json:"updatedAt"`
	Nodes         []Node `json:"nodes"`
	DownloadRoute string `json:"downloadRoute"`
}
type Library struct {
	Version int      `json:"version"`
	Records []Record `json:"subscriptions"`
}
type Fetcher func(context.Context, string) ([]byte, error)

func Empty() Library { return Library{Version: 2, Records: []Record{}} }
func (lib Library) Record(id string) (Record, error) {
	for _, r := range lib.Records {
		if r.ID == id {
			return r, nil
		}
	}
	return Record{}, errors.New("保存的订阅不存在")
}
func (lib Library) Node(subID, nodeID string) (Node, error) {
	r, e := lib.Record(subID)
	if e != nil {
		return Node{}, e
	}
	for _, n := range r.Nodes {
		if n.ID == nodeID && n.Supported {
			return n, nil
		}
	}
	return Node{}, errors.New("所选订阅节点已缺失或不支持；请明确重新选择")
}
func (r Record) Summary() model.SubscriptionSummary {
	n := 0
	for _, node := range r.Nodes {
		if node.Supported {
			n++
		}
	}
	return model.SubscriptionSummary{ID: r.ID, Name: r.Name, SourceKind: r.SourceKind, UpdatedAt: r.UpdatedAt, NodeCount: len(r.Nodes), SupportedNodeCount: n, DownloadRoute: func() string { r, _ := NormalizeDownloadRoute(r.DownloadRoute); return r }()}
}
func (lib Library) Summaries() []model.SubscriptionSummary {
	out := make([]model.SubscriptionSummary, 0, len(lib.Records))
	for _, r := range lib.Records {
		out = append(out, r.Summary())
	}
	return out
}
func (lib Library) Prepare(ctx context.Context, input model.SubscriptionInput, fetch Fetcher) (Record, error) {
	return lib.prepare(ctx, input, fetch, Parse)
}

// PrepareWithURIConverter preserves atomic candidate semantics while requiring
// the packaged converter for URI input. YAML uses the same native-leaf boundary.
func (lib Library) PrepareWithURIConverter(ctx context.Context, input model.SubscriptionInput, fetch Fetcher, converter URIConverter) (Record, error) {
	return lib.prepare(ctx, input, fetch, func(content []byte) ([]Node, error) {
		return ParseWithURIConverter(ctx, content, converter)
	})
}

func (lib Library) prepare(ctx context.Context, input model.SubscriptionInput, fetch Fetcher, parse func([]byte) ([]Node, error)) (Record, error) {
	var r Record
	if !validName(strings.TrimSpace(input.Name)) || (input.URL == "") == (len(input.Content) == 0) {
		return r, errors.New("请填写订阅名称，并且只选择链接或文件内容其中一种")
	}
	if input.ID != "" {
		if _, e := lib.Record(input.ID); e != nil {
			return r, e
		}
	} else if len(lib.Records) >= MaxSubscriptions {
		return r, errors.New("最多保存 8 个独立订阅")
	}
	downloadRoute := DownloadDirect
	if input.URL != "" {
		var e error
		downloadRoute, e = NormalizeDownloadRoute(input.DownloadRoute)
		if e != nil {
			return r, e
		}
	}
	content := input.Content
	kind := "file"
	if input.URL != "" {
		if fetch == nil {
			if downloadRoute == DownloadActiveExitGuard {
				return r, ErrActiveRouteUnavailable
			}
			fetch = Fetch
		}
		var e error
		content, e = fetch(ctx, input.URL)
		if e != nil {
			if safe := ResponseFailure(e); safe != nil {
				return r, safe
			}
			return r, errors.New("订阅下载失败；可改为导入本地节点文件")
		}
		kind = "url"
	}
	if ctx.Err() != nil {
		return r, errors.New("订阅操作已取消")
	}
	nodes, e := parse(content)
	if e != nil {
		return r, e
	}
	id := input.ID
	if id == "" {
		var b [16]byte
		if _, e = rand.Read(b[:]); e != nil {
			return r, ErrStorage
		}
		id = hex.EncodeToString(b[:])
	}
	for i := range nodes {
		if nodes[i].Config == nil {
			nodes[i].Config = map[string]any{}
		}
	}
	return Record{ID: id, Name: strings.TrimSpace(input.Name), SourceKind: kind, SourceURL: input.URL, UpdatedAt: time.Now().UTC().Format(time.RFC3339), Nodes: nodes, DownloadRoute: downloadRoute}, nil
}
func (lib *Library) Put(r Record) error {
	for i := range lib.Records {
		if lib.Records[i].ID == r.ID {
			lib.Records[i] = r
			return nil
		}
	}
	if len(lib.Records) >= MaxSubscriptions {
		return ErrStorage
	}
	lib.Records = append(lib.Records, r)
	return nil
}
func (lib *Library) Delete(id string) error {
	for i, r := range lib.Records {
		if r.ID == id {
			lib.Records = append(lib.Records[:i:i], lib.Records[i+1:]...)
			return nil
		}
	}
	return errors.New("保存的订阅不存在")
}
func validID(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func Encode(lib Library) ([]byte, error) {
	lib.Version = 2
	records := make([]Record, len(lib.Records))
	copy(records, lib.Records)
	lib.Records = records
	for i := range lib.Records {
		route, e := NormalizeDownloadRoute(lib.Records[i].DownloadRoute)
		if e != nil {
			return nil, ErrStorage
		}
		lib.Records[i].DownloadRoute = route
	}
	data, e := json.Marshal(lib)
	if e != nil || len(data)+1 > MaxBytes {
		return nil, ErrStorage
	}
	if _, e = Decode(data); e != nil {
		return nil, e
	}
	return append(data, '\n'), nil
}
func Decode(data []byte) (Library, error) {
	empty := Empty()
	if len(data) == 0 || len(data) > MaxBytes || strictJSON(data) != nil {
		return empty, ErrStorage
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	// Native leaf counters and windows can exceed float64's exact integer range.
	// Preserve their JSON representation so authentication/identity never changes
	// during private storage round trips. Typed envelope integers remain strict.
	d.UseNumber()
	var lib Library
	if d.Decode(&lib) != nil || (lib.Version != 1 && lib.Version != 2) || lib.Records == nil || len(lib.Records) > MaxSubscriptions {
		return empty, ErrStorage
	}
	var fields struct {
		Records []map[string]json.RawMessage `json:"subscriptions"`
	}
	if json.Unmarshal(data, &fields) != nil || len(fields.Records) != len(lib.Records) {
		return empty, ErrStorage
	}
	seen := map[string]bool{}
	for index, r := range lib.Records {
		_, hasRoute := fields.Records[index]["downloadRoute"]
		if lib.Version == 1 && hasRoute || lib.Version == 2 && (!hasRoute || r.DownloadRoute == "") {
			return empty, ErrStorage
		}
		route, e := NormalizeDownloadRoute(r.DownloadRoute)
		if e != nil {
			return empty, ErrStorage
		}
		if r.SourceKind == "file" && route != DownloadDirect {
			return empty, ErrStorage
		}
		r.DownloadRoute = route
		lib.Records[index].DownloadRoute = route
		if !validID(r.ID, 32) || seen[r.ID] || !validName(r.Name) || r.Nodes == nil || len(r.Nodes) == 0 || len(r.Nodes) > MaxNodes {
			return empty, ErrStorage
		}
		seen[r.ID] = true
		if _, e := time.Parse(time.RFC3339, r.UpdatedAt); e != nil {
			return empty, ErrStorage
		}
		if r.SourceKind != "url" && r.SourceKind != "file" || r.SourceKind == "url" && validateDownloadURL(r.SourceURL) != nil || r.SourceKind == "file" && r.SourceURL != "" {
			return empty, ErrStorage
		}
		ids := map[string]bool{}
		for _, n := range r.Nodes {
			if !validID(n.ID, 64) || ids[n.ID] || !validName(n.Name) || n.Type != safeType(n.Type) || n.Config == nil {
				return empty, ErrStorage
			}
			ids[n.ID] = true
			if n.Supported {
				if n.Reason != "" || ValidateCanonicalNode(n.Config) != nil || Identity(n.Config) != n.ID || n.Config["type"] != n.Type {
					return empty, ErrStorage
				}
			} else if len(n.Config) != 0 || !validUnsupportedReason(n.Reason) {
				return empty, ErrStorage
			}
		}
	}
	return lib, nil
}

// Reject duplicate keys, explicit nulls and trailing JSON before typed decoding.
func strictJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return ErrStorage
		}
		t, e := d.Token()
		if e != nil || t == nil {
			return ErrStorage
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					token, e := d.Token()
					key, ok := token.(string)
					if e != nil || !ok || seen[key] {
						return ErrStorage
					}
					seen[key] = true
					if value(depth+1) != nil {
						return ErrStorage
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return ErrStorage
				}
			case '[':
				for d.More() {
					if value(depth+1) != nil {
						return ErrStorage
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return ErrStorage
				}
			default:
				return ErrStorage
			}
		}
		return nil
	}
	if value(0) != nil {
		return ErrStorage
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrStorage
	}
	return nil
}
