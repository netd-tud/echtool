package echfmt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/OmarTariq612/goech"
)

const (
	FormatText   = "text"
	FormatJSON   = "json"
	FormatTable  = "table"
	FormatBase64 = "b64"
)

func ValidFormat(format string) bool {
	switch format {
	case FormatText, FormatJSON, FormatTable, FormatBase64:
		return true
	default:
		return false
	}
}

func ValidateFormat(format string) error {
	if ValidFormat(format) {
		return nil
	}
	return fmt.Errorf("invalid --format %q: must be %q, %q, %q or %q",
		format, FormatText, FormatJSON, FormatTable, FormatBase64)
}

type Options struct {
	Format string

	ShowConfig int

	IncludeBase64 bool

	// RetryConfiguration ECH connection worked
	ECHAccepted *bool

	// Peer, DNS and Validations enrich the JSON envelope with probe outcome
	// details; unset values are omitted. The other formats ignore them.
	Peer        *PeerInfo
	DNS         *DNSInfo
	Validations []ValidationInfo
}

// PeerInfo describes the TLS connection a probe established.
type PeerInfo struct {
	Address        string `json:"address,omitempty"`
	NegotiatedALPN string `json:"negotiated_alpn,omitempty"`
	TLSVersion     string `json:"tls_version,omitempty"`
}

// DNSInfo is the outcome of comparing the server's RetryConfigs against the
// ECH config published in the target's DNS HTTPS RR.
type DNSInfo struct {
	Found   bool                      `json:"found"`
	Matches bool                      `json:"matches"`
	Configs SerializableECHConfigList `json:"configs,omitempty"`
}

// ValidationInfo is the outcome of re-offering one retry config in a fresh
// handshake.
type ValidationInfo struct {
	Index    int    `json:"index"`
	ConfigID uint8  `json:"config_id"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// Input parser
func ParseECHConfigList(raw string) (string, error) {
	idx := echTokenIndex(raw)
	if idx == -1 {
		return raw, nil
	}

	value := strings.TrimSpace(raw[idx+len("ech="):])
	if strings.HasPrefix(value, `"`) {
		value = value[1:]
		if end := strings.IndexByte(value, '"'); end != -1 {
			value = value[:end]
		}
	} else if end := strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || r == ')'
	}); end != -1 {
		value = value[:end]
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf(`found "ech=" in input but no value followed`)
	}
	return value, nil
}

func echTokenIndex(s string) int {
	for off := 0; ; {
		idx := strings.Index(s[off:], "ech=")
		if idx == -1 {
			return -1
		}
		idx += off
		if idx == 0 || unicode.IsSpace(rune(s[idx-1])) {
			return idx
		}
		off = idx + len("ech=")
	}
}

func DecodeECHConfigList(raw string) (goech.ECHConfigList, error) {
	parsed, err := ParseECHConfigList(raw)
	if err != nil {
		return nil, err
	}
	list, err := goech.ECHConfigListFromBase64(parsed)
	if err != nil {
		return nil, fmt.Errorf("parsing ECHConfigList: %w", err)
	}
	return list, nil
}

func Render(out io.Writer, configs goech.ECHConfigList, opts Options) error {
	selected, err := selectConfigs(configs, opts.ShowConfig)
	if err != nil {
		return err
	}

	if opts.Format == FormatBase64 {
		b64, err := selected.ToBase64()
		if err != nil {
			return fmt.Errorf("encoding ECHConfigList to base64: %w", err)
		}
		_, err = fmt.Fprintln(out, b64)
		return err
	}

	list := ToSerializableList(selected)
	switch opts.Format {
	case FormatJSON:
		return renderJSON(out, selected, list, opts)
	case FormatTable:
		if err := renderTable(out, list); err != nil {
			return err
		}
	default:
		if err := renderText(out, list); err != nil {
			return err
		}
	}
	if opts.IncludeBase64 {
		return renderBase64Line(out, selected)
	}
	return nil
}

func selectConfigs(configs goech.ECHConfigList, show int) (goech.ECHConfigList, error) {
	if show < 0 {
		return configs, nil
	}
	if show >= len(configs) {
		return nil, fmt.Errorf("--show-config %d out of range: list has %d config(s)", show, len(configs))
	}
	return goech.ECHConfigList{configs[show]}, nil
}

func renderBase64Line(out io.Writer, configs goech.ECHConfigList) error {
	b64, err := configs.ToBase64()
	if err != nil {
		return fmt.Errorf("encoding ECHConfigList to base64: %w", err)
	}
	_, err = fmt.Fprintf(out, "\nECHConfigList (base64): %s\n", b64)
	return err
}

type SerializableECHConfig struct {
	Version       uint16                        `json:"ech_version"`
	ConfigID      uint8                         `json:"ech_config_id"`
	RawPublicName string                        `json:"ech_public_name"`
	MaxNameLength uint8                         `json:"ech_max_name_length"`
	RawExtensions string                        `json:"ech_raw_extensions"`
	KEM           string                        `json:"ech_kem"`
	CipherSuites  []SerializableHpkeCipherSuite `json:"ech_cipher_suites"`
	PublicKey     string                        `json:"ech_public_key"`
}

type SerializableHpkeCipherSuite struct {
	Kdf      uint16 `json:"kdf"`
	KdfName  string `json:"kdf_name"`
	Aead     uint16 `json:"aead"`
	AeadName string `json:"aead_name"`
}

type SerializableECHConfigList []SerializableECHConfig

func ToSerializableList(configs goech.ECHConfigList) SerializableECHConfigList {
	list := make(SerializableECHConfigList, len(configs))
	for i, config := range configs {
		list[i] = ToSerializable(config)
	}
	return list
}

func KDFName(kdf uint16) string {
	if int(kdf) < len(goech.KDFMapping) && goech.KDFMapping[kdf] != "" {
		return goech.KDFMapping[kdf]
	}
	return "unknown"
}

func AEADName(aead uint16) string {
	if int(aead) < len(goech.AEADMapping) && goech.AEADMapping[aead] != "" {
		return goech.AEADMapping[aead]
	}
	return "unknown"
}

func ToSerializable(config goech.ECHConfig) SerializableECHConfig {
	cipherSuites := make([]SerializableHpkeCipherSuite, len(config.CipherSuites))
	for i, cs := range config.CipherSuites {
		cipherSuites[i] = SerializableHpkeCipherSuite{
			Kdf:      uint16(cs.KDF),
			KdfName:  KDFName(uint16(cs.KDF)),
			Aead:     uint16(cs.AEAD),
			AeadName: AEADName(uint16(cs.AEAD)),
		}
	}
	var publicKey string
	if raw, err := config.PublicKey.MarshalBinary(); err != nil {
		publicKey = fmt.Sprintf("<unmarshalable: %v>", err)
	} else {
		publicKey = hex.EncodeToString(raw)
	}

	return SerializableECHConfig{
		Version:       config.Version,
		ConfigID:      config.ConfigID,
		RawPublicName: string(config.RawPublicName),
		MaxNameLength: config.MaxNameLength,
		RawExtensions: hex.EncodeToString(config.RawExtensions),
		KEM:           config.KEM.Scheme().Name(),
		CipherSuites:  cipherSuites,
		PublicKey:     publicKey,
	}
}

func renderJSON(out io.Writer, configs goech.ECHConfigList, list SerializableECHConfigList, opts Options) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if !opts.IncludeBase64 && opts.ECHAccepted == nil &&
		opts.Peer == nil && opts.DNS == nil && len(opts.Validations) == 0 {
		return enc.Encode(list)
	}
	payload := struct {
		Configs             SerializableECHConfigList `json:"configs"`
		ECHAccepted         *bool                     `json:"ech_accepted,omitempty"`
		ECHConfigListBase64 string                    `json:"ech_config_list_base64,omitempty"`
		Peer                *PeerInfo                 `json:"peer,omitempty"`
		DNS                 *DNSInfo                  `json:"dns,omitempty"`
		Validations         []ValidationInfo          `json:"validations,omitempty"`
	}{Configs: list, ECHAccepted: opts.ECHAccepted, Peer: opts.Peer, DNS: opts.DNS, Validations: opts.Validations}
	if opts.IncludeBase64 {
		b64, err := configs.ToBase64()
		if err != nil {
			return fmt.Errorf("encoding ECHConfigList to base64: %w", err)
		}
		payload.ECHConfigListBase64 = b64
	}
	return enc.Encode(payload)
}

func renderTable(out io.Writer, configs SerializableECHConfigList) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "#\tVERSION\tCONFIG_ID\tPUBLIC_NAME\tMAX_LEN\tEXTENSIONS\tKEM\tCIPHER_SUITES\tPUBLIC_KEY")
	for i, c := range configs {
		suites := make([]string, len(c.CipherSuites))
		for j, cs := range c.CipherSuites {
			suites[j] = fmt.Sprintf("%s/%s", cs.KdfName, cs.AeadName)
		}
		extensions := c.RawExtensions
		if extensions == "" {
			extensions = "-"
		}
		fmt.Fprintf(w, "%d\t%d\t%d\t%s\t%d\t%s\t%s\t%s\t%s\n",
			i, c.Version, c.ConfigID, c.RawPublicName, c.MaxNameLength, extensions,
			c.KEM, strings.Join(suites, ", "), c.PublicKey)
	}
	return w.Flush()
}

func renderText(out io.Writer, configs SerializableECHConfigList) error {
	for i, c := range configs {
		fmt.Fprintf(out, "ECHConfig #%d\n", i)
		fmt.Fprintf(out, "  Version:         0x%04x\n", c.Version)
		fmt.Fprintf(out, "  Config ID:       %d\n", c.ConfigID)
		fmt.Fprintf(out, "  Public Name:     %s\n", c.RawPublicName)
		fmt.Fprintf(out, "  Max Name Length: %d\n", c.MaxNameLength)
		if c.RawExtensions != "" {
			fmt.Fprintf(out, "  Extensions:      %s\n", c.RawExtensions)
		}
		fmt.Fprintf(out, "  KEM:             %s\n", c.KEM)
		fmt.Fprintf(out, "  Cipher Suites:\n")
		for _, cs := range c.CipherSuites {
			fmt.Fprintf(out, "    - KDF %s (0x%04x), AEAD %s (0x%04x)\n",
				cs.KdfName, cs.Kdf, cs.AeadName, cs.Aead)
		}
		fmt.Fprintf(out, "  Public Key:      %s\n", c.PublicKey)
		if i != len(configs)-1 {
			fmt.Fprintln(out)
		}
	}
	return nil
}
