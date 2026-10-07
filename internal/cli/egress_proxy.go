package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/apomonosi/sandboxing/internal/egress"
)

// newEgressProxyCmd is the hidden command a backend without a native
// egress ACL (Lima) re-executes agentctl with, in the background, to run a
// sandbox's host-side egress filtering proxy — see internal/egress. It's
// not meant to be run by hand, which is why it's hidden, but it's an
// ordinary command (and shows up verbatim in `start --preview` output) so
// nothing about what runs is concealed.
func newEgressProxyCmd() *cobra.Command {
	var opts egress.ServeOptions
	cmd := &cobra.Command{
		Use:    egress.CommandName,
		Short:  "Run a sandbox's host-side egress filtering proxy (started by agentctl itself)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			opts.Log = cmd.ErrOrStderr()
			return egress.Serve(ctx, opts)
		},
	}
	cmd.Flags().StringVar(&opts.Listen, egress.FlagListen, "", "loopback address to listen on, e.g. 127.0.0.1:51234")
	cmd.Flags().StringVar(&opts.PolicyPath, egress.FlagPolicy, "", "egress policy file to enforce")
	cmd.Flags().StringVar(&opts.PIDFile, egress.FlagPIDFile, "", "pid file, held locked while the proxy runs")
	for _, f := range []string{egress.FlagListen, egress.FlagPolicy, egress.FlagPIDFile} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}
