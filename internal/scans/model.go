package scans

import (
	"context"
	"errors"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
)

// Status is the lifecycle state of a scan.
type Status string

// Scan lifecycle states.
const (
	StatusQueued      Status = "queued"
	StatusRunning     Status = "running"
	StatusCompleted   Status = "completed"
	StatusFailed      Status = "failed"
	StatusCancelled   Status = "cancelled"
	StatusInterrupted Status = "interrupted"
)

var (
	// ErrNotFound indicates that a requested scan or profile does not exist.
	ErrNotFound = errors.New("scan not found")
	// ErrScanActive indicates that an active scan cannot be deleted.
	ErrScanActive = errors.New("an active scan cannot be deleted")
	// ErrPrivilegeRequired indicates that a scan option needs elevated privileges.
	ErrPrivilegeRequired = errors.New("OS detection requires privileged launch")
)

// Scan contains the persisted configuration, state, and summary of a scan.
type Scan struct {
	ID               string     `json:"id"`
	Target           string     `json:"target"`
	ProfileID        string     `json:"profileId"`
	OSDetection      bool       `json:"osDetection"`
	Status           Status     `json:"status"`
	Arguments        []string   `json:"arguments"`
	CreatedAt        time.Time  `json:"createdAt"`
	StartedAt        *time.Time `json:"startedAt,omitempty"`
	FinishedAt       *time.Time `json:"finishedAt,omitempty"`
	ExitCode         *int       `json:"exitCode,omitempty"`
	Output           string     `json:"output"`
	Error            string     `json:"error,omitempty"`
	NmapVersion      string     `json:"nmapVersion,omitempty"`
	XMLOutputVersion string     `json:"xmlOutputVersion,omitempty"`
	HostsUp          int        `json:"hostsUp"`
	HostsDown        int        `json:"hostsDown"`
	HostsTotal       int        `json:"hostsTotal"`
	Ownership        *Ownership `json:"ownership,omitempty"`
}

// Profile is a reusable, validated set of Nmap arguments.
type Profile struct {
	ID           string     `json:"id"`
	Label        string     `json:"label"`
	ArgumentText string     `json:"argumentText"`
	Arguments    []string   `json:"arguments"`
	BuiltIn      bool       `json:"builtIn"`
	CreatedAt    *time.Time `json:"createdAt,omitempty"`
	UpdatedAt    *time.Time `json:"updatedAt,omitempty"`
}

// ScanRequest configures a new scan.
type ScanRequest struct {
	Target              string
	ProfileID           string
	AdditionalArguments []string
	OSDetection         bool
}

// Capabilities describes the features and provider tools available at runtime.
type Capabilities struct {
	Privileged         bool               `json:"privileged"`
	OSDetection        bool               `json:"osDetection"`
	ToolActivity       bool               `json:"toolActivity"`
	RouteMapping       bool               `json:"routeMapping"`
	RouteTool          string             `json:"routeTool,omitempty"`
	RouteMappingReason string             `json:"routeMappingReason,omitempty"`
	Providers          []providers.Status `json:"providers"`
}

// RouteHop is one observed hop on a route to a host.
type RouteHop struct {
	TTL       int     `json:"ttl"`
	Address   string  `json:"address,omitempty"`
	Loss      float64 `json:"loss,omitempty"`
	LatencyMS float64 `json:"latencyMs,omitempty"`
}

// HostRoute contains the discovered path to a target.
type HostRoute struct {
	Target string     `json:"target"`
	Tool   string     `json:"tool,omitempty"`
	Hops   []RouteHop `json:"hops"`
	Error  string     `json:"error,omitempty"`
}

// RouteMap groups the routes recorded for a scan.
type RouteMap struct {
	Tool   string      `json:"tool"`
	Routes []HostRoute `json:"routes"`
}

// Result is the normalized summary of an Nmap XML document.
type Result struct {
	NmapVersion      string
	XMLOutputVersion string
	HostsUp          int
	HostsDown        int
	HostsTotal       int
	Hosts            []HostObservation
}

// HostObservation is the normalized network data collected for one host.
type HostObservation struct {
	ID          int64                `json:"id"`
	State       string               `json:"state"`
	StateReason string               `json:"stateReason,omitempty"`
	Provisional bool                 `json:"provisional"`
	Addresses   []Address            `json:"addresses"`
	Hostnames   []Hostname           `json:"hostnames"`
	Ports       []Port               `json:"ports"`
	OSStatus    string               `json:"osStatus,omitempty"`
	OSMatches   []OSMatch            `json:"osMatches,omitempty"`
	Ownership   *Ownership           `json:"ownership,omitempty"`
	Evidence    []providers.Evidence `json:"evidence,omitempty"`
}

// OSMatch is an operating-system fingerprint reported by Nmap.
type OSMatch struct {
	Name     string    `json:"name"`
	Accuracy int       `json:"accuracy"`
	Classes  []OSClass `json:"classes,omitempty"`
}

// OSClass provides structured details for an operating-system match.
type OSClass struct {
	Type       string   `json:"type,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	Family     string   `json:"family,omitempty"`
	Generation string   `json:"generation,omitempty"`
	Accuracy   int      `json:"accuracy"`
	CPEs       []string `json:"cpes,omitempty"`
}

// Ownership describes the registered allocation containing a host address.
type Ownership struct {
	Organization string   `json:"organization,omitempty"`
	NetworkName  string   `json:"networkName,omitempty"`
	Range        string   `json:"range,omitempty"`
	CIDR         string   `json:"cidr,omitempty"`
	City         string   `json:"city,omitempty"`
	Region       string   `json:"region,omitempty"`
	Country      string   `json:"country,omitempty"`
	Origin       string   `json:"origin,omitempty"`
	Sources      []string `json:"sources,omitempty"`
}

// Address is a network address observed for a host.
type Address struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Vendor  string `json:"vendor,omitempty"`
}

// Hostname is a name associated with a host.
type Hostname struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// Port describes the state and detected service of a network port.
type Port struct {
	Protocol    string `json:"protocol"`
	Number      int    `json:"number"`
	State       string `json:"state"`
	StateReason string `json:"stateReason,omitempty"`
	Service     string `json:"service,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	ExtraInfo   string `json:"extraInfo,omitempty"`
	Method      string `json:"method,omitempty"`
	Confidence  int    `json:"confidence,omitempty"`
	Tunnel      string `json:"tunnel,omitempty"`
}

// HostSummary is the compact host representation used in paginated lists.
type HostSummary struct {
	ID            int64  `json:"id"`
	State         string `json:"state"`
	Address       string `json:"address"`
	AddressType   string `json:"addressType"`
	Vendor        string `json:"vendor,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	OpenPortCount int    `json:"openPortCount"`
	WebAvailable  bool   `json:"webAvailable"`
	Provisional   bool   `json:"provisional"`
}

// HostPage is one page of host summaries.
type HostPage struct {
	Items  []HostSummary `json:"items"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

// Event is a scan lifecycle, progress, tool, evidence, or output update.
type Event struct {
	Type     string              `json:"type"`
	ScanID   string              `json:"scanId,omitempty"`
	Scan     *Scan               `json:"scan,omitempty"`
	Host     *HostObservation    `json:"host,omitempty"`
	Progress *Progress           `json:"progress,omitempty"`
	Tool     *ToolActivity       `json:"tool,omitempty"`
	Evidence *providers.Evidence `json:"evidence,omitempty"`
	Text     string              `json:"text,omitempty"`
	Stream   string              `json:"stream,omitempty"`
}

// ToolActivity reports whether a tool is currently active for a scan.
type ToolActivity struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Active bool   `json:"active"`
}

// Store persists scans and their profiles, hosts, routes, and evidence.
type Store interface {
	Create(context.Context, Scan) error
	List(context.Context) ([]Scan, error)
	Get(context.Context, string) (Scan, error)
	Delete(context.Context, string) error
	MarkStarted(context.Context, string, time.Time) error
	AppendOutput(context.Context, string, string) error
	Finish(context.Context, string, Status, time.Time, *int, string) error
	SaveResult(context.Context, string, Result) error
	SaveHost(context.Context, string, HostObservation) (HostObservation, error)
	EnsureHost(context.Context, string, Address, []Hostname, string) (HostObservation, bool, error)
	SaveHostEnrichment(context.Context, string, Address, []Hostname, *Ownership) (HostObservation, error)
	SaveScanOwnership(context.Context, string, *Ownership) (Scan, error)
	SaveSummary(context.Context, string, Result) error
	ListHosts(context.Context, string, int, int) (HostPage, error)
	GetHost(context.Context, string, int64) (HostObservation, error)
	SaveRoute(context.Context, string, HostRoute) error
	ListRoutes(context.Context, string) (RouteMap, error)
	InterruptRunning(context.Context, time.Time) error
	ListProfiles(context.Context) ([]Profile, error)
	GetProfile(context.Context, string) (Profile, error)
	CreateProfile(context.Context, Profile) error
	UpdateProfile(context.Context, Profile) error
	DeleteProfile(context.Context, string) error
	CreateProviderRun(context.Context, providers.Run) error
	FinishProviderRun(context.Context, string, string, time.Time, string) error
	SaveEvidence(context.Context, string, providers.Evidence) (providers.Evidence, error)
	ListEvidence(context.Context, string, providers.EvidenceQuery) ([]providers.Evidence, error)
	ListTools(context.Context, string) ([]ToolActivity, error)
}
