package cmd

import (
	"fmt"
	"os"

	"github.com/onepeerlabs/wimp"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "wimp-cli",
	Short: "Command line interface for wimp",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("version    : ", wimp.Version)
	},
}

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