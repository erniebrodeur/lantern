package providers

import (
	"context"
	"encoding/json"
	"time"
)

// Descriptor identifies a provider and the capability it implements.
type Descriptor struct {
	ID           string         `json:"id"`
	Capability   string         `json:"capability"`
	Label        string         `json:"label"`
	SupportedOS  []string       `json:"supportedOs"`
	OSPriorities map[string]int `json:"-"`
}

// Status reports whether a provider can run on the current host.
type Status struct {
	Capability string `json:"capability"`
	ProviderID string `json:"provider,omitempty"`
	Label      string `json:"label,omitempty"`
	OS         string `json:"os"`
	Status     string `json:"status"`
	Available  bool   `json:"available"`
	Path       string `json:"path,omitempty"`
	Version    string `json:"version,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Request contains the target and options supplied to a provider run.
type Request struct {
	RunID     string            `json:"runId"`
	Target    string            `json:"target"`
	Arguments []string          `json:"arguments,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
}

// EntityRef identifies an entity referenced by a piece of evidence.
type EntityRef struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

// Evidence is a versioned observation emitted by a provider.
type Evidence struct {
	ID             int64           `json:"id,omitempty"`
	ProviderRunID  string          `json:"providerRunId,omitempty"`
	ProviderID     string          `json:"provider,omitempty"`
	Capability     string          `json:"capability,omitempty"`
	Kind           string          `json:"kind"`
	Subject        EntityRef       `json:"subject"`
	Object         *EntityRef      `json:"object,omitempty"`
	PayloadVersion int             `json:"payloadVersion"`
	Payload        json.RawMessage `json:"payload"`
	ObservedAt     time.Time       `json:"observedAt"`
	Confidence     float64         `json:"confidence"`
}

// Progress describes a provider's current unit of work.
type Progress struct {
	Phase     string `json:"phase,omitempty"`
	Task      string `json:"task,omitempty"`
	Percent   string `json:"percent,omitempty"`
	Remaining string `json:"remaining,omitempty"`
	Completed int    `json:"completed,omitempty"`
	Total     int    `json:"total,omitempty"`
}

// Event is a progress, evidence, output, or completion update from a provider.
type Event struct {
	Type     string    `json:"type"`
	Progress *Progress `json:"progress,omitempty"`
	Evidence *Evidence `json:"evidence,omitempty"`
	Message  string    `json:"message,omitempty"`
	Stream   string    `json:"stream,omitempty"`
	ExitCode *int      `json:"exitCode,omitempty"`
}

// Selection pairs a resolved provider with its probed status.
type Selection struct {
	Provider Provider
	Status   Status
}

// EmitFunc receives events produced during a provider run.
type EmitFunc func(Event) error

// Provider discovers one kind of network evidence.
type Provider interface {
	Describe() Descriptor
	Probe(context.Context) Status
	Run(context.Context, Request, EmitFunc) error
}

// Run records the lifecycle of one provider invocation for a scan.
type Run struct {
	ID         string     `json:"id"`
	ScanID     string     `json:"scanId"`
	Capability string     `json:"capability"`
	ProviderID string     `json:"provider"`
	Label      string     `json:"label,omitempty"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// EvidenceQuery filters evidence stored for a scan.
type EvidenceQuery struct {
	Kind        string
	SubjectType string
	SubjectKey  string
	Limit       int
}

// ObservedHost is the minimal host identity discovered by a provider.
type ObservedHost struct {
	Hostname string `json:"hostname,omitempty"`
	Reason   string `json:"reason,omitempty"`
}
