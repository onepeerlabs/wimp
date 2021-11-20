package cmd

import (
	"fmt"
	"os"
	"os/signal"

	ipfslite "github.com/datahop/ipfs-lite/pkg"
	datahop "github.com/datahop/ipfs-lite/version"
	logging "github.com/ipfs/go-log/v2"
	"github.com/onepeerlabs/wimp"
	"github.com/spf13/cobra"
)

func init() {
	logging.SetLogLevel("wimp-cmd", "Debug")
}

func DaemonCmd(comm *ipfslite.Common) *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "",
		Long: `

		`,
		Run: func(cmd *cobra.Command, args []string) {
			// TODO: add verbosity flag
			err := ipfslite.Start(comm)
			cfg, err := comm.Repo.Config()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			log.Debug("swarmPort : ", cfg.SwarmPort)
			log.Debug("version : ", wimp.Version)
			log.Debug("datahop version : ", datahop.Version)
			log.Debug("dataDir : ", comm.Root)
			var sigChan chan os.Signal
			sigChan = make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt)
			for {
				select {
				case <-sigChan:
					comm.Cancel()
					return
				case <-comm.Context.Done():
					return
				}
			}
		},
	}
}
