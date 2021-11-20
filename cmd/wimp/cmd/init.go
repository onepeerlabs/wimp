package cmd

import (
	ipfslite "github.com/datahop/ipfs-lite/pkg"
	"github.com/spf13/cobra"
)

func InitCmd(comm *ipfslite.Common) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "",
		Long: `

		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ipfslite.Init(comm)
			if err != nil {
				return err
			}
			return nil
		},
	}
}
