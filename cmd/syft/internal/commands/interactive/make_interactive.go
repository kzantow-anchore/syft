package interactive

import (
	"errors"
	"fmt"
	"github.com/gookit/color"
	"github.com/mattn/go-shellwords"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
)

func MakeInteractive(cmd *cobra.Command) *cobra.Command {
	interactive := true
	cmd.Flags().BoolVarP(&interactive, "interactive", "", interactive, "run commands in interactive mode")
	baseRunE := cmd.RunE
	cmd.InitDefaultHelpFlag()
	cmd.RunE = interactiveRunE(cmd, &interactive, baseRunE)
	cmd.AddCommand(
		&cobra.Command{
			Use: "quit",
			RunE: func(cmd *cobra.Command, args []string) error {
				os.Exit(0)
				return nil
			},
		},
	)
	return cmd
}

var whitespace = regexp.MustCompile(`\s+`)

func interactiveRunE(root *cobra.Command, interactive *bool, baseRunE func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(_ *cobra.Command, commandLineArgs []string) error {
		if !*interactive {
			return baseRunE(root, commandLineArgs)
		}
		fd := int(os.Stdin.Fd())
		state, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		defer func() {
			_ = term.Restore(fd, state)
		}()

		terminal := term.NewTerminal(os.Stdin, "\r\n> ")
		terminal.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
			switch key {
			case 9: // tab
				parts, err := shellwords.Parse(line)
				if err == nil {
					return autocompleteTerms(parts, pos, root)
				}
			}
			return line, pos, false
		}

		readLine := func() string {
			line, err := terminal.ReadLine()
			if err != nil {
				return "quit"
			}
			return strings.TrimSpace(whitespace.ReplaceAllString(line, " "))
		}

		defer send(&os.Stdout, terminal)()
		defer send(&os.Stderr, terminal)()
		//root.SetOut(os.Stdout)

		for line := readLine(); ; line = readLine() {
			err = nil
			parts, err := shellwords.Parse(line)
			if err == nil {
				args, flags := splitFlags(parts)
				cmd, args := findCommand(args, root)
				if cmd != nil {
					//cmd.ResetFlags()
					//s := pflag.NewFlagSet(cmd.Name(), pflag.ContinueOnError)
					//s.AddFlagSet(cmd.Flags())
					//err = s.Parse(flags)
					//cmd.Flags().AddFlagSet(s)

					// how to reset?
					err = cmd.ParseFlags(flags)
					if err == nil {
						err = runCommand(cmd, args)
					}
					if errors.Is(err, pflag.ErrHelp) {
						err = cmd.Help()
					}
				} else {
					err = fmt.Errorf("no command found matching: %s", line)
				}
			}
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, color.Red.Text("%v"), err)
			}
		}

		return nil
	}
}

func send(out **os.File, terminal *term.Terminal) func() {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	original := *out
	*out = w

	running := atomic.Bool{}
	running.Store(true)

	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		cr := []byte{'\r'}
		buf := make([]byte, 0, 128)
		for running.Load() {
			read, err := r.Read(buf)
			if err != nil {
				panic(err)
			}
			if read > 0 {
				write := buf[0:read]
				// prepend \t to newlines
				nl := slices.Index(write, '\n')
				for nl >= 0 {
					_, err = terminal.Write(write[0:nl])
					if err != nil {
						panic(err)
					}
					_, err = terminal.Write(cr)
					if err != nil {
						panic(err)
					}
					write = write[nl:]
				}
				_, err = terminal.Write(write)
				if err != nil {
					panic(err)
				}
			}
		}
	}()

	return func() {
		running.Store(false)
		_ = w.Close()
		*out = original
	}
}

func runCommand(cmd *cobra.Command, args []string) error {
	if cmd.Run != nil {
		cmd.Run(cmd, args)
		return nil
	}
	if cmd.RunE != nil {
		return cmd.RunE(cmd, args)
	}
	return fmt.Errorf("command not runnable")
}

func splitFlags(parts []string) (args []string, flags []string) {
	for i, part := range parts {
		if strings.HasPrefix(part, "-") {
			return args, parts[i:]
		}
		args = append(args, part)
	}
	return args, nil
}

func findCommand(parts []string, root *cobra.Command) (*cobra.Command, []string) {
	if len(parts) == 0 {
		return root, nil
	}
	cmd := parts[0]
	for _, child := range root.Commands() {
		name := child.Name()
		if name == cmd {
			if len(parts) > 1 {
				sub, args := findCommand(parts[1:], child)
				if sub != nil {
					return sub, args
				}
			}
			if len(parts) > 1 {
				return child, parts[1:]
			}
			return child, nil
		}
	}
	return nil, nil
}

func autocompleteTerms(parts []string, pos int, root *cobra.Command) (string, int, bool) {
	if len(parts) == 0 {
		return "", pos, false
	}
	cmd := parts[0]
	remain := ""
	if len(parts) > 1 {
		remain = parts[1]
	}
	for _, child := range root.Commands() {
		name := child.Name()
		if strings.HasPrefix(name, cmd) {
			if pos < len(cmd)+1 {
				return name + " " + remain, len(name) + 1, true // have a command, just move the cursor to end of the match
			}
			if name == cmd && len(parts) > 1 {
				line2, pos2, ok := autocompleteTerms(parts[1:], pos-len(name)-1, child)
				if ok {
					return name + " " + line2, len(name) + 1 + pos2, ok
				}
			}
		}
	}
	line2, pos2, ok := autocompleteArgs(parts, pos, root)
	if ok {
		return line2, pos2, ok
	}
	return "", 0, false
}

func autocompleteArgs(parts []string, pos int, root *cobra.Command) (string, int, bool) {
	if len(parts) == 0 {
		return "", 0, false
	}
	var dashedFlagNames []string
	root.Flags().VisitAll(func(flag *pflag.Flag) {
		dashedFlagNames = append(dashedFlagNames, "--"+flag.Name) // , "-"+flag.Name)
		if flag.Shorthand != "" {
			dashedFlagNames = append(dashedFlagNames, "-"+flag.Shorthand)
		}
	})
	total := 0
	for i, part := range parts {
		if pos < total+len(part)+1 {
			if strings.HasPrefix(part, "-") {
				for _, name := range dashedFlagNames {
					if strings.HasPrefix(name, part) {
						suffix := ""
						if i == len(parts)-1 {
							suffix = " "
						}
						parts[i] = name
						return strings.Join(parts, " ") + suffix, total + len(name) + 1, true
					}
				}
			}
			break
		}
		total += len(part) + 1
	}
	return "", 0, false
}
