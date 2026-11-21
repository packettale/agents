package main

import (
	"github.com/packettale/agents/cmds/cmdbase"
	"github.com/spf13/cobra"
)

var recoverIPTablesFlag bool

func init() {
	rootCmd.Flags().BoolVar(&recoverIPTablesFlag, "recover-iptables", false, "restore firewall rules")
}

func runPlatformSpecifics(cmd *cobra.Command, args []string) {
	switch {
	case printVersion:
		runFlagCmd(cmdbase.Version, cmd, args)
	case recoverIPTablesFlag:
		runFlagCmd(recoverIPTables, cmd, args)
	}
}
