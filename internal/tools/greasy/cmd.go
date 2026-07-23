package greasy

import (
	"github.com/spf13/cobra"

	"github.com/netd-tud/echtool/internal/cli"
	"github.com/netd-tud/echtool/pkg/dial"
)

type rootConfig struct {
	use, short, long    string
	tcpShort, quicShort string
	requireConfig       bool
	echConfigHelp       string
}

func newRootCmd(rc rootConfig) *cobra.Command {
	o := &options{requireConfig: rc.requireConfig}

	root := &cobra.Command{
		Use:           rc.use,
		Short:         rc.short,
		Long:          rc.long,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	o.addFlags(root, rc.echConfigHelp)
	cli.AddLogLevelFlag(root)

	root.AddCommand(newDialCmd("tcp", rc.tcpShort, o, "443", nil, dial.TCP))
	root.AddCommand(newDialCmd("quic", rc.quicShort, o, "443", []string{"h3"}, dial.QUIC))
	return root
}

func NewCmd() *cobra.Command {
	return newRootCmd(rootConfig{
		use:   "greasy",
		short: "Probe a server's ECH support via a GREASE handshake",
		long: "greasy offers a GREASE (or --ech-config) ECHConfig to a TLS server and " +
			"reports whether ECH is accepted or rejected with RetryConfigs. Connect over " +
			"TCP or QUIC via the tcp and quic subcommands.",
		tcpShort:      "Probe ECH over TCP",
		quicShort:     "Probe ECH over QUIC",
		requireConfig: false,
		echConfigHelp: "base64 ECHConfigList to offer (default: random/GREASE)",
	})
}

// We use the same source code for greasy and echConn (conn)
func NewConnCmd() *cobra.Command {
	return newRootCmd(rootConfig{
		use:   "conn",
		short: "Connect to a server offering a provided ECH config",
		long: "conn offers a provided --ech-config ECHConfigList to a TLS server and " +
			"attempts a connection, reporting whether ECH is accepted or rejected with " +
			"RetryConfigs. Individual ECH fields can be overridden. Connect over TCP or " +
			"QUIC via the tcp and quic subcommands.",
		tcpShort:      "Connect over TCP",
		quicShort:     "Connect over QUIC",
		requireConfig: true,
		echConfigHelp: "base64 ECHConfigList to offer (required)",
	})
}

// newDialCmd builds a transport subcommand. defaultALPN is applied when the user
// passes no --alpn (QUIC mandates ALPN, so it defaults to h3).
func newDialCmd(use, short string, o *options, defaultPort string, defaultALPN []string, dialFn dial.Fn) *cobra.Command {
	return &cobra.Command{
		Use:           use + " <target>",
		Short:         short,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			if len(o.tls.ALPN) == 0 {
				o.tls.ALPN = defaultALPN
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			host, address := cli.ParseTarget(args[0], defaultPort)
			address = o.dns.Address(address)
			pubName := o.overrides.PubName
			if pubName == "" {
				pubName = host
			}
			list, err := o.resolveConfigList(cmd.Flags(), pubName)
			if err != nil {
				return err
			}
			return run(cmd.OutOrStdout(), o, host, address, list, dialFn)
		},
	}
}
