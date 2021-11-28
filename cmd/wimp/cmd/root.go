package cmd

import (
	"fmt"
	"os"

	logging "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
)

const (
	root = ".wimp"
	port = "36000"
)

var (
	log = logging.Logger("wimp-cmd")

	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		Use:   "wimp-cli",
		Short: "Command line interface for wimp",
		Run: func(cmd *cobra.Command, args []string) {
			initPrompt()
		},
	}
)

func Execute() {
	wimpCli := `
              __                                       __ __ 
             |  \                                     |  |  \
 __   __   __ \$$______ ____   ______          _______| $$\$$
|  \ |  \ |  |  |      \    \ /      \ ______ /       | $|  \
| $$ | $$ | $| $| $$$$$$\$$$$|  $$$$$$|      |  $$$$$$| $| $$
| $$ | $$ | $| $| $$ | $$ | $| $$  | $$\$$$$$| $$     | $| $$
| $$_/ $$_/ $| $| $$ | $$ | $| $$__/ $$      | $$_____| $| $$
 \$$   $$   $| $| $$ | $$ | $| $$    $$       \$$     | $| $$
  \$$$$$\$$$$ \$$\$$  \$$  \$| $$$$$$$         \$$$$$$$\$$\$$
                             | $$                            
                             | $$                            
                              \$$                        
`
	fmt.Println(wimpCli)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
