package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	logging "github.com/ipfs/go-log/v2"

	uds "github.com/asabya/go-ipc-uds"
	ipfslite "github.com/datahop/ipfs-lite/pkg"
	"github.com/onepeerlabs/wimp"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	argSeparator = "$^~@@*"
)

var (
	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		Use:   "wimp-cli",
		Short: "Command line interface for wimp",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("version    : ", wimp.Version)
		},
	}
	log = logging.Logger("wimp-cmd")

	sockName = "wimp-uds.sock"
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

	comm, err := ipfslite.New(".wimp", "36000")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var allCommands []*cobra.Command
	allCommands = append(
		allCommands,
		InitCmd(comm),
		DaemonCmd(comm),
		StopCmd(comm),
	)

	for _, i := range allCommands {
		rootCmd.AddCommand(i)
	}
	socketPath := filepath.Join("/tmp", sockName)
	if os.Args[1] != "daemon" && uds.IsIPCListening(socketPath) {
		opts := uds.Options{
			SocketPath: socketPath,
		}
		r, w, c, err := uds.Dialer(opts)
		if err != nil {
			log.Error(err)
			goto Execute
		}
		defer c()
		err = w(strings.Join(os.Args[1:], argSeparator))
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}
		v, err := r()
		if err != nil {
			log.Error(err)
			os.Exit(1)

		}
		fmt.Println(v)
		return
	}
	if os.Args[1] == "daemon" {
		if uds.IsIPCListening(socketPath) {
			fmt.Println("Datahop daemon is already running")
			return
		}
		_, err := os.Stat(socketPath)
		if !os.IsNotExist(err) {
			err := os.Remove(socketPath)
			if err != nil {
				log.Error(err)
				os.Exit(1)
			}
		}
		opts := uds.Options{
			SocketPath: socketPath,
		}
		in, err := uds.Listener(comm.Context, opts)
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}
		go func() {
			for {
				client := <-in
				go func() {
					for {
						ip, err := client.Read()
						if err != nil {
							break
						}
						if len(ip) == 0 {
							break
						}
						commandStr := string(ip)
						log.Debug("run command :", commandStr)
						var (
							childCmd *cobra.Command
							flags    []string
						)
						command := strings.Split(commandStr, argSeparator)
						if rootCmd.TraverseChildren {
							childCmd, flags, err = rootCmd.Traverse(command)
						} else {
							childCmd, flags, err = rootCmd.Find(command)
						}
						if err != nil {
							err = client.Write([]byte(err.Error()))
							if err != nil {
								log.Error("Write error", err)
								client.Close()
							}
							break
						}
						childCmd.Flags().VisitAll(func(f *pflag.Flag) {
							err := f.Value.Set(f.DefValue)
							if err != nil {
								log.Error("Unable to set flags ", childCmd.Name(), f.Name, err.Error())
							}
						})
						if err := childCmd.Flags().Parse(flags); err != nil {
							log.Error("Unable to parse flags ", err.Error())
							err = client.Write([]byte(err.Error()))
							if err != nil {
								log.Error("Write error", err)
								client.Close()
							}
							break
						}
						outBuf := new(bytes.Buffer)
						childCmd.SetOut(outBuf)
						if childCmd.Args != nil {
							if err := childCmd.Args(childCmd, flags); err != nil {
								err = client.Write([]byte(err.Error()))
								if err != nil {
									log.Error("Write error", err)
									client.Close()
								}
								break
							}
						}
						if childCmd.PreRunE != nil {
							if err := childCmd.PreRunE(childCmd, flags); err != nil {
								err = client.Write([]byte(err.Error()))
								if err != nil {
									log.Error("Write error", err)
									client.Close()
								}
								break
							}
						} else if childCmd.PreRun != nil {
							childCmd.PreRun(childCmd, command)
						}

						if childCmd.RunE != nil {
							if err := childCmd.RunE(childCmd, flags); err != nil {
								err = client.Write([]byte(err.Error()))
								if err != nil {
									log.Error("Write error", err)
									client.Close()
								}
								break
							}
						} else if childCmd.Run != nil {
							childCmd.Run(childCmd, flags)
						}

						out := outBuf.Next(outBuf.Len())
						outBuf.Reset()
						err = client.Write(out)
						if err != nil {
							log.Error("Write error", err)
							client.Close()
							break
						}
					}
				}()
			}
		}()
	}

Execute:
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
