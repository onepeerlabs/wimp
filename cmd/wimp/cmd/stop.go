package cmd

import (
	ipfslite "github.com/datahop/ipfs-lite/pkg"
	"github.com/spf13/cobra"
)

func StopCmd(comm *ipfslite.Common) *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "",
		Long: `

		`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("Daemon Stopped")
			comm.Cancel()
		},
	}
}
