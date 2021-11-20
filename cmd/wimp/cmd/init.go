package cmd

import (
	ipfslite "github.com/datahop/ipfs-lite/pkg"
	"github.com/spf13/cobra"
)

// initCmd
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		comm, err := ipfslite.New(".wimp", "0")
		if err != nil {
			return err
		}
		err = ipfslite.Init(comm)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
