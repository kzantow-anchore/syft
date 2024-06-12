package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

const (
	newLine            = "\r\n"
	setFileGlobKeyword = "glob"
	lsKeyword          = "ls"
	findRegexKeyword   = "find"
	sourceKeyword      = "source"
	listKeyword        = "list"
	addKeyword         = "add"
	delKeyword         = "del"
)

var (
	allKeywords    = []string{sourceKeyword, findRegexKeyword, setFileGlobKeyword, listKeyword, addKeyword, delKeyword}
	sourceKeywords = []string{listKeyword, addKeyword, delKeyword}
)

type inspectOpts struct { // this struct is not included in configurations
	Sources     []string
	Glob        string
	Find        string
	ContextSize int
	RowWidth    int
	Interactive bool
	Get         bool
}

func (o *inspectOpts) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Glob, setFileGlobKeyword, "", "glob to use to specify which file(s) to operate on")
	flags.StringVarP(&o.Find, findRegexKeyword, "", "regex to search for in each matching file")
	flags.IntVarP(&o.ContextSize, "context", "", "number of bytes to capture on either side of matches for context")
	flags.IntVarP(&o.RowWidth, "width", "", "match row width to display")
	flags.StringArrayVarP(&o.Sources, sourceKeyword, "", "additional sources to inspect")
	flags.BoolVarP(&o.Interactive, "interactive", "", "prompt for refinement of sources, files, and find expressions")
	flags.BoolVarP(&o.Get, "get", "", "if files result in a single file, return the bytes to stdout")
}

var _ clio.FlagAdder = (*inspectOpts)(nil)

func Inspect() *cobra.Command {
	opts := &inspectOpts{
		Glob:        "**/*",
		ContextSize: 200,
		RowWidth:    35,
	}

	cmd := &cobra.Command{
		Use:   "inspect [SOURCE]? [FILE GLOB]?",
		Short: "inspect sources",
		Args:  cobra.RangeArgs(0, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := os.Stdout
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()
			if len(args) > 0 {
				opts.Sources = append(opts.Sources, args[0])
			}
			if opts.Glob == "" && len(args) > 1 {
				opts.Glob = args[1]
			}
			return runInspect(cmd.Context(), opts, out)
		},
		Hidden: true,
	}

	opts.AddFlags(fangs.NewPFlagSet(log.Get(), cmd.Flags()))

	return cmd
}

//nolint:funlen,gocognit,gocyclo
func runInspect(ctx context.Context, opts *inspectOpts, writer io.Writer) error {
	// validate regex early to avoid waiting for downloads that will just get deleted
	if opts.Find != "" {
		_, err := regexp.Compile(opts.Find)
		if err != nil {
			return err
		}
	}
	var sourceLock sync.Mutex
	var sources []source.Source
	defer func() {
		sourceLock.Lock()
		defer sourceLock.Unlock()
		for _, s := range sources {
			if s != nil {
				_ = s.Close()
			}
		}
	}()
	addSource := func(userInput string) error {
		_, _ = fmt.Fprintf(os.Stderr, "loading source: '%s'..."+newLine, userInput)
		sourceType, userInput := stereoscope.ExtractSchemeSource(userInput, allSourceProviderTags()...)
		var sourceTypes []string
		if sourceType != "" {
			sourceTypes = append(sourceTypes, sourceType)
		}
		catalogOpts := options.DefaultCatalog()
		src, err := getSource(ctx, &catalogOpts, userInput, sourceTypes...)
		if err != nil {
			return err
		}
		if src == nil {
			return fmt.Errorf("unable to get source for: %s", userInput)
		}
		sourceLock.Lock()
		defer sourceLock.Unlock()
		sources = append(sources, src)
		slices.SortFunc(sources, func(a, b source.Source) int {
			return strings.Compare(sourceTag(a), sourceTag(b))
		})
		return nil
	}
	for _, s := range opts.Sources {
		err := addSource(s)
		if err != nil {
			return err
		}
	}

	if opts.Interactive {
		whitespace := regexp.MustCompile(`\s+`)

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
				newLine, pos = autocompleteTerms(line, pos, allKeywords...)
				return newLine, pos, true
			default:
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
		writer = terminal
	nextLine:
		for line := readLine(); ; line = readLine() {
			err = nil
			parts := whitespace.Split(line, 2)
			switch parts[0] {
			case "q", "quit", "exit":
				break nextLine
			case lsKeyword:
				if len(parts) < 2 {
					err = inspectSources(opts, sources, writer, opts.Glob, "")
				} else {
					glob := parts[1]
					err = inspectSources(opts, sources, writer, glob, "")
				}
			case setFileGlobKeyword:
				if len(parts) < 2 {
					_, _ = fmt.Fprintf(writer, "  %s"+newLine, opts.Glob)
				} else {
					opts.Glob = parts[1]
					err = inspectSources(opts, sources, writer, opts.Glob, "")
				}
			case findRegexKeyword:
				if len(parts) < 2 {
					_, _ = fmt.Fprintf(writer, "  %s"+newLine, opts.Find)
				} else {
					_, err = regexp.Compile(parts[1])
					if err == nil {
						err = inspectSources(opts, sources, writer, opts.Glob, parts[1])
					}
				}
			case sourceKeyword:
				if len(parts) < 2 {
					err = fmt.Errorf("must specify operation: %v", sourceKeywords)
					break
				}
				parts = whitespace.Split(parts[1], 2)
				switch parts[0] {
				case listKeyword:
					sourceListTable(sources, writer)
					continue nextLine
				case addKeyword:
					if len(parts) < 2 {
						err = fmt.Errorf("must specify %s <source>", addKeyword)
						break
					}
					err = addSource(parts[1])
					if err == nil {
						sourceListTable(sources, writer)
						continue nextLine
					}
				case delKeyword:
					if len(parts) < 2 {
						err = fmt.Errorf("must specify %s <tag|id>", delKeyword)
						break
					}
					match := parts[1]
					for i := range sources {
						s := sources[i]
						if s.Describe().ID == match || sourceTag(s) == match {
							err = sources[i].Close()
							if err != nil {
								_, _ = fmt.Fprintf(os.Stderr, "error closing source: %v", err)
							}
							sources = append(sources[0:i], sources[i+1:]...)
							sourceListTable(sources, writer)
							continue nextLine
						}
					}
					err = fmt.Errorf("could not find source matching '%s', use ID or Tag", match)
				}
			default:
				err = fmt.Errorf("unknown command: %s ... use: %v", parts[0], allKeywords)
			}
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, color.Red.Text(strings.ReplaceAll(fmt.Sprintf("%v", err), "\n", newLine))+newLine)
			}
		}
	} else {
		return inspectSources(opts, sources, writer, opts.Glob, opts.Find)
	}
	return nil
}

func sourceListTable(sources []source.Source, writer io.Writer) {
	if len(sources) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "no sources added; use "+sourceKeyword+" "+addKeyword+newLine)
		return
	}
	tw := table.NewWriter()
	style := table.StyleDefault
	style.Format.Header = text.FormatDefault
	style.Format.Row = text.FormatDefault
	style.Options.DrawBorder = false
	style.Options.SeparateColumns = false
	style.Options.SeparateFooter = false
	style.Options.SeparateHeader = true
	tw.SetStyle(style)
	tw.AppendHeader(table.Row{"Tag", "ID"})
	for _, s := range sources {
		tw.AppendRow(table.Row{sourceTag(s), s.Describe().ID})
	}
	_, _ = fmt.Fprintf(writer, strings.ReplaceAll(tw.Render(), "\n", newLine)+newLine)
}

func autocompleteTerms(line string, pos int, keywords ...string) (string, int) {
	if len(line) == 0 {
		return line, pos
	}
	parts := strings.Split(line, " ")
	nextKeywordInLine := func(part string) string {
		if len(part) == 0 {
			return part
		}
	nextKeyword:
		for _, keyword := range keywords {
			for i := 0; i < len(part); i++ {
				if part[i] != keyword[i] {
					continue nextKeyword
				}
			}
			return keyword
		}
		return part
	}
	partPos := 0
	for i, part := range parts {
		if pos > partPos+len(part) {
			partPos += len(part) + 1 // + width of space
			continue
		}
		next := nextKeywordInLine(part)
		if next == part {
			return line, pos
		}
		if i == len(parts)-1 {
			next += " "
		}
		parts[i] = next
		line = strings.Join(parts, " ")
		return line, partPos + len(next)
	}
	return line, pos
}

func sourceTag(s source.Source) string {
	d := s.Describe()
	return fmt.Sprintf("%s:%s", d.Name, d.Version)
}

func inspectSources(opts *inspectOpts, sources []source.Source, writer io.Writer, glob, find string) error {
	var errs []error
	if len(sources) == 0 {
		_, _ = fmt.Fprintf(writer, "  no sources defined, use: %s %s"+newLine, sourceKeyword, addKeyword)
	}
	for _, src := range sources {
		if len(sources) > 0 {
			_, _ = fmt.Fprintf(writer, sourceTag(src)+newLine)
			_, _ = fmt.Fprintf(writer, strings.Repeat("-", opts.RowWidth*3)+newLine)
		}
		errs = append(errs, inspectSource(opts, src, writer, glob, find))
	}
	return errors.Join(errs...)
}

func inspectSource(opts *inspectOpts, src source.Source, writer io.Writer, glob, find string) error {
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		return err
	}

	if glob == "" {
		glob = "**/*"
	}
	locations, err := resolver.FilesByGlob(glob)
	if err != nil {
		return err
	}

	if opts.Get {
		return returnFile(opts, locations, resolver, writer)
	}

	if find == "" {
		return outputLocations(writer, locations)
	}

	return outputMatches(resolver, writer, locations, opts.ContextSize, opts.RowWidth, find, ansiStartColor(), ansiEndColor())
}

func returnFile(opts *inspectOpts, locations []file.Location, resolver file.Resolver, writer io.Writer) error {
	if len(locations) == 0 {
		return fmt.Errorf("no files found at: %s", opts.Glob)
	}
	if len(locations) > 1 {
		return fmt.Errorf("multiple files found at: %s", opts.Glob)
	}
	rdr, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return err
	}
	defer internal.CloseAndLogError(rdr, locations[0].RealPath)
	_, err = io.Copy(writer, rdr)
	return err
}

func outputLocations(writer io.Writer, locations []file.Location) error {
	slices.SortFunc(locations, func(a, b file.Location) int {
		return strings.Compare(a.Path(), b.Path())
	})
	for _, l := range locations {
		_, _ = fmt.Fprintf(writer, "  %s"+newLine, l.Path())
	}
	return nil
}

//nolint:funlen,gocognit
func outputMatches(resolver file.Resolver, writer io.Writer, locations []file.Location, contextSize int, rowWidth int, searchExpression string, matchStartColor, matchEndColor string) error {
	regex, err := regexp.Compile(searchExpression)
	if err != nil {
		return fmt.Errorf("unable to compile regex: %w", err)
	}
	slices.SortFunc(locations, func(a, b file.Location) int {
		return strings.Compare(a.Path(), b.Path())
	})
	for _, l := range locations {
		err = matchLocation(resolver, writer, l, contextSize, rowWidth, regex, matchStartColor, matchEndColor)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "    ERROR: %v"+newLine, err)
			return err
		}
	}
	return nil
}

func matchLocation(resolver file.Resolver, writer io.Writer, l file.Location, contextSize int, rowWidth int, regex *regexp.Regexp, matchStartColor, matchEndColor string) error {
	_, _ = fmt.Fprintf(writer, "  %s"+newLine, l.Path())
	rdr, err := resolver.FileContentsByLocation(l)
	if err != nil {
		return err
	}
	defer internal.CloseAndLogError(rdr, l.RealPath)
	contents, err := io.ReadAll(rdr)
	if err != nil {
		return err
	}
	matches := regex.FindAllIndex(contents, -1)
	if len(matches) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "    NO MATCHES"+newLine)
		return nil
	}

	for i, match := range matches {
		start := match[0]
		end := match[1]

		contextStart := start - contextSize
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := end + contextSize
		if contextEnd >= len(contents) {
			contextEnd = len(contents) - 1
		}
		contextEnd -= contextEnd % rowWidth
		snippet := contents[contextStart:contextEnd]
		startInContext := start - contextStart
		endInContext := end - contextStart

		_, _ = fmt.Fprintf(writer, "    MATCH %v (index: %v-%v, showing: %v-%v len: %v)"+newLine, i+1, start, end, contextStart, contextEnd, contextEnd-contextStart)

		for row := 0; row < len(snippet); row += rowWidth {
			rowEnd := row + rowWidth
			if rowEnd >= len(snippet) {
				rowEnd = len(snippet) - 1
			}
			rowBytes := snippet[row:rowEnd]
			hexPairs := sliceToString(rowBytes, hexify, " ", matchStartColor, matchEndColor, rowWidth, startInContext-row, endInContext-row-1)
			printable := sliceToString(rowBytes, printableChar, "", matchStartColor, matchEndColor, rowWidth, startInContext-row, endInContext-row-1)
			_, _ = fmt.Fprintf(writer, "    %v    %v"+newLine, hexPairs, printable)
		}
		if len(regex.SubexpNames()) > 1 { // first name is "", or the entire match
			_, _ = fmt.Fprintf(writer, "    EXTRACTED:"+newLine)
			for _, submatch := range regex.FindAllStringSubmatch(string(snippet), -1) {
				for i, name := range regex.SubexpNames() {
					if name == "" {
						continue
					}
					_, _ = fmt.Fprintf(writer, "        %v: %v"+newLine, name, submatch[i])
				}
			}
		}
		_, _ = fmt.Fprintf(writer, ""+newLine)
	}
	return nil
}

func hexify(b byte) string {
	return fmt.Sprintf("%02X", b)
}

func sliceToString[T any](contents []T, stringer func(T) string, pad string, matchStartColor, matchEndColor string, rowWidth, start, end int) string {
	buf := bytes.Buffer{}
	if start < 0 && end >= 0 {
		buf.WriteString(matchStartColor)
	}
	for i, c := range contents {
		if i == start {
			buf.WriteString(matchStartColor)
		}
		buf.WriteString(stringer(c))
		if i == end {
			buf.WriteString(matchEndColor)
		}
		buf.WriteString(pad)
	}
	if end >= len(contents) && start < len(contents) {
		buf.WriteString(matchEndColor)
	}
	// pad line to full rowWidth
	if len(contents) < rowWidth {
		var empty T
		spaces := append([]rune(stringer(empty)), []rune(pad)...)
		for i := range spaces {
			spaces[i] = ' '
		}
		for i := len(contents); i < rowWidth; i++ {
			buf.WriteString(string(spaces))
		}
	}
	return buf.String()
}

func ansiStartColor() string {
	return color.StartSet + color.New(color.OpUnderscore, color.OpReverse).String() + "m"
}

func ansiEndColor() string {
	return color.ResetSet
}

func printableChar(c byte) string {
	if c < 32 || c == 127 {
		return string('\u2400' + rune(c))
	}
	return string(rune(c))
}
