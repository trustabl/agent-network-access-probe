package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const licenseText = `Trustabl Probe (autofix)
Copyright 2026 Trustabl (Component Factory AI, Inc.)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Full text: https://github.com/trustabl/trustabl-probe/blob/main/LICENSE`

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Print license and copyright information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(licenseText)
	},
}

// showLicenseBannerOnce prints a concise license notice the first time autofix
// runs on this machine. A marker file in the OS config dir suppresses the
// banner on subsequent runs. The banner is skipped when the user invokes the
// "license" subcommand (they are already reading the full terms).
func showLicenseBannerOnce(subcmd string) {
	if subcmd == "license" {
		return
	}
	marker, err := licenseMarkerPath()
	if err != nil {
		return
	}
	if _, err := os.Stat(marker); err == nil {
		return // already shown
	}
	fmt.Fprintln(os.Stderr, "────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr, "  Trustabl Probe (autofix)  ·  Apache-2.0")
	fmt.Fprintln(os.Stderr, "  github.com/trustabl/trustabl-probe")
	fmt.Fprintln(os.Stderr, "  Run `autofix license` for license and copyright info")
	fmt.Fprintln(os.Stderr, "────────────────────────────────────────────────────────")
	_ = os.MkdirAll(filepath.Dir(marker), 0o755)
	_ = os.WriteFile(marker, []byte{}, 0o644)
}

func licenseMarkerPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "autofix", "license_shown"), nil
}
