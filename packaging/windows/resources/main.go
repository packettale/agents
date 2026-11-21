// Command resources creates Windows icon resources for the service executable.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tc-hib/winres"
)

func main() {
	icon := flag.String("icon", "", "PacketTale ICO asset")
	out := flag.String("out", "", "core source directory")
	flag.Parse()
	if err := generate(*icon, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(iconPath, outputDir string) error {
	if iconPath == "" || outputDir == "" {
		return errors.New("resources requires -icon and -out")
	}
	file, err := os.Open(iconPath)
	if err != nil {
		return err
	}
	icon, readErr := winres.LoadICO(file)
	if err = errors.Join(readErr, file.Close()); err != nil {
		return err
	}
	resources := winres.ResourceSet{}
	if err := resources.SetIcon(winres.ID(1), icon); err != nil {
		return err
	}
	for _, arch := range []winres.Arch{winres.ArchAMD64, winres.ArchARM64} {
		path := filepath.Join(outputDir, "icon_windows_"+string(arch)+".syso")
		output, err := os.Create(path)
		if err != nil {
			return err
		}
		err = errors.Join(resources.WriteObject(output, arch), output.Close())
		if err != nil {
			_ = os.Remove(path)
			return err
		}
	}
	return nil
}
