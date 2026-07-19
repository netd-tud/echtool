module github.com/jmuecke/echtools

go 1.26.3

require (
	github.com/OmarTariq612/goech v0.0.1
	github.com/cloudflare/circl v1.3.3
	github.com/sirupsen/logrus v1.9.4
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	golang.org/x/net v0.55.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

// Patched copy of x/net v0.55.0: fixes a panic in quic's
// cryptoStream.handleCrypto that a rejected ECH offer triggers by design.
// See third_party/golang.org/x/net/README-ECHTOOLS.md for the diff, the
// upstream report, and how to drop this once upstream ships the fix.
replace golang.org/x/net => ./third_party/golang.org/x/net
