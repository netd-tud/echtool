package echtest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Record is one observation persisted to a domain's append-only log. The log is
// a write-only audit trail: it captures every observed config with its timestamp
// for offline analysis, but is not read back — a run reconstructs its report
// from in-memory state, not from disk.
type Record struct {
	Timestamp           time.Time `json:"timestamp"`
	Domain              string    `json:"domain"`
	Source              string    `json:"source"` // grease | retry | dns
	Event               string    `json:"event"`
	ECHConfigListBase64 string    `json:"ech_config_list_base64,omitempty"`
}

// Observation sources.
const (
	SourceGrease = "grease"
	SourceRetry  = "retry"
	SourceDNS    = "dns"
	SourceProbe  = "probe" // a periodic re-offer of the config under test
)

// Death reasons: what kind of failure the fatal streak that killed a config
// consisted of. Only ech_rejected is a clean signal that the server stopped
// accepting the config; connect_failed can equally be network trouble, so its
// lifetime measurement should be discounted.
const (
	DeathECHRejected   = "ech_rejected"   // every failed attempt was an ECH rejection (server answered with RetryConfigs)
	DeathConnectFailed = "connect_failed" // no failed attempt was an ECH rejection (network or handshake trouble)
	DeathMixed         = "mixed"          // the streak mixed rejections and other failures
)

// Summary is the outcome of one bootstrap-to-death sample, appended as a line
// to the domain's summary log when that sample ends (SIGINT, --max-runtime,
// or the config being declared dead). A domain accumulates one line per
// sample (see --samples), so consecutive lifetimes/grace-periods for the same
// domain can be compared against each other for consistency.
type Summary struct {
	Timestamp   time.Time  `json:"timestamp"` // when the summary was written
	Domain      string     `json:"domain"`
	Sample      int        `json:"sample"` // 1-indexed position in this domain's sequence of samples
	BootstrapOK bool       `json:"bootstrap_ok"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`

	// RepeatedConfig marks a rerun whose bootstrap returned the same config the
	// previous sample tested to death, so its lifetime can be discounted when
	// comparing consecutive samples.
	RepeatedConfig bool `json:"repeated_config,omitempty"`

	// Per-channel rotation signals. DNSChanged/RetryChanged are when each
	// channel first observed a config other than the one under test;
	// DNSRotations/RetryRotations count every distinct config seen since
	// (including that first one).
	DNSChanged     *time.Time `json:"dns_changed,omitempty"`
	DNSRotations   int        `json:"dns_rotations,omitempty"`
	RetryChanged   *time.Time `json:"retry_changed,omitempty"`
	RetryRotations int        `json:"retry_rotations,omitempty"`

	// RotationChanged/RotationSource are the earliest of DNSChanged/RetryChanged
	// - whichever channel noticed the rotation first - and drive OverlapSeconds
	// (the "grace period": how long the config under test kept being accepted
	// after that first rotation signal).
	RotationChanged *time.Time `json:"rotation_changed,omitempty"`
	RotationSource  *string    `json:"rotation_source,omitempty"` // "dns" | "retry"

	Alive           bool       `json:"alive"` // true if the config was still accepted when observation ended
	DeclaredAt      *time.Time `json:"declared_at,omitempty"`
	DeathReason     string     `json:"death_reason,omitempty"` // one of the Death* constants; set when death was declared
	Death           *time.Time `json:"death,omitempty"`
	LifetimeSeconds *int64     `json:"lifetime_seconds,omitempty"`
	OverlapSeconds  *int64     `json:"overlap_seconds,omitempty"`
}

// store is an append-only JSON-lines persistence layer, one file per domain under
// a base directory. Appends are serialized so concurrent per-domain trackers do
// not interleave partial lines.
type store struct {
	dir string
	mu  sync.Mutex
}

// openStore creates (if needed) the state directory and returns a store rooted at
// it.
func openStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating state dir %q: %w", dir, err)
	}
	return &store{dir: dir}, nil
}

// sanitize maps characters that are unsafe in filenames (e.g. the ':' of a
// host:port) to '_'.
func sanitize(domain string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return '_'
		default:
			return r
		}
	}, domain)
}

// path returns the log file path for a domain.
func (s *store) path(domain string) string {
	return filepath.Join(s.dir, sanitize(domain)+".jsonl")
}

// summaryPath returns the summary log path for a domain.
func (s *store) summaryPath(domain string) string {
	return filepath.Join(s.dir, sanitize(domain)+".summary.jsonl")
}

// append writes one record as a JSON line to the domain's log. A failed write
// is logged rather than returned: the log is an audit trail alongside the
// primary work, and no caller can do more than surface the problem.
func (s *store) append(r Record) {
	if err := s.appendRecord(r); err != nil {
		logrus.WithError(err).Warnf("%s: appending observation record", r.Domain)
	}
}

func (s *store) appendRecord(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.path(r.Domain), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening log for %s: %w", r.Domain, err)
	}
	defer f.Close()

	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("encoding record: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("writing record: %w", err)
	}
	return nil
}

// writeSummary appends sum as a line to the domain's summary log, one entry
// per sample.
func (s *store) writeSummary(domain string, sum Summary) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.summaryPath(domain), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening summary log for %s: %w", domain, err)
	}
	defer f.Close()

	line, err := json.Marshal(sum)
	if err != nil {
		return fmt.Errorf("encoding summary: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("writing summary for %s: %w", domain, err)
	}
	return nil
}
