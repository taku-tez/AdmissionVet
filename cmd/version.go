package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AdmissionVet/admissionvet/internal/versions"
)

// NewVersionCommand returns the `admissionvet version` command group.
func NewVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Manage policy generation version history",
	}
	cmd.AddCommand(newVersionListCommand())
	cmd.AddCommand(newVersionRollbackCommand())
	return cmd
}

func newVersionListCommand() *cobra.Command {
	var outputDir string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List policy generation history for an output directory",
		Example: `  admissionvet version list --output output/
  admissionvet version list -o ./policies`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersionList(outputDir)
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "output", "Output directory to inspect")
	return cmd
}

func runVersionList(outputDir string) error {
	h, err := versions.Load(outputDir)
	if err != nil {
		return err
	}

	if len(h.Entries) == 0 {
		fmt.Printf("No version history found in %s\n", outputDir)
		fmt.Printf("Run 'admissionvet generate' or 'admissionvet apply' to create the first version.\n")
		return nil
	}

	fmt.Printf("Version history for %s (%d entries):\n\n", outputDir, len(h.Entries))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tTIMESTAMP\tENGINE\tSOURCE\tFILES")
	fmt.Fprintln(w, "-------\t---------\t------\t------\t-----")
	for _, e := range h.Entries {
		fmt.Fprintf(w, "v%d\t%s\t%s\t%s\t%d\n",
			e.Version,
			e.Timestamp.Format("2006-01-02 15:04:05 UTC"),
			e.Engine,
			e.Source,
			len(e.Files),
		)
	}
	w.Flush()

	latest := h.Entries[len(h.Entries)-1]
	fmt.Printf("\nCurrent: v%d  To rollback: admissionvet version rollback --output %s --to <N>\n",
		latest.Version, outputDir)
	return nil
}

func newVersionRollbackCommand() *cobra.Command {
	var (
		outputDir     string
		targetVersion int
	)

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback policies to a previous version",
		Long: `Restores the output directory to a previously generated version.
Rollback is only possible if the stash for that version still exists
(last 5 versions are kept).

Example:
  admissionvet version rollback --output output/ --to 2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersionRollback(outputDir, targetVersion)
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "output", "Output directory")
	cmd.Flags().IntVar(&targetVersion, "to", 0, "Target version number (required)")
	cmd.MarkFlagRequired("to")
	return cmd
}

func runVersionRollback(outputDir string, targetVersion int) error {
	h, err := versions.Load(outputDir)
	if err != nil {
		return err
	}

	found := false
	for _, e := range h.Entries {
		if e.Version == targetVersion {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("version %d not found in history", targetVersion)
	}

	fmt.Printf("Rolling back %s to v%d...\n", outputDir, targetVersion)
	if err := versions.Rollback(outputDir, targetVersion); err != nil {
		return err
	}
	fmt.Printf("Rollback complete. Current state now reflects v%d.\n", targetVersion)
	return nil
}
