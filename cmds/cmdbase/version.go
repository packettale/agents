package cmdbase

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/packettale/agents/base/info"
)

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the installed version.",
	RunE:  Version,
}

func Version(cmd *cobra.Command, args []string) error {
	fmt.Printf("PacketTale %s (%s/%s)\nLicensed under %s.\n", info.VersionNumber(), runtime.GOOS, runtime.GOARCH, info.GetInfo().License)
	return nil
}
