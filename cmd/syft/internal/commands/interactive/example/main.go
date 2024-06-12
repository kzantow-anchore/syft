package main

import (
	"fmt"
	"github.com/anchore/syft/cmd/syft/internal/commands/interactive"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func main() {
	root := &cobra.Command{}

	ls := &cobra.Command{
		Use:  "ls",
		RunE: runFunc("ls"),
	}
	root.AddCommand(ls)

	cp := &cobra.Command{
		Use:  "cp",
		RunE: runFunc("cp"),
	}
	var s, t string
	cp.Flags().StringVarP(&s, "from", "s", "asdf", "from usage")
	cp.Flags().StringVar(&t, "to", "", "to usage")
	cp.Flags().BoolP("quiet", "q", false, "quiet usage")
	root.AddCommand(cp)

	nested := &cobra.Command{
		Use:  "nest",
		RunE: runFunc("nest"),
	}
	root.AddCommand(nested)

	sub := &cobra.Command{
		Use:  "sub",
		RunE: runFunc("nest_sub"),
	}
	nested.AddCommand(sub)

	cmd := &cobra.Command{
		Use:  "cmd",
		RunE: runFunc("nest_sub_cmd"),
	}
	sub.AddCommand(cmd)

	_ = interactive.MakeInteractive(root).Execute()
}

func runFunc(command string) func(_ *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		var values []any
		cmd.Flags().VisitAll(func(flag *pflag.Flag) {
			values = append(values, flag.Value)
		})
		fmt.Printf("running: %s with args: %v and flags %v\n", command, args, values)
		return nil
	}
}
