package dynamic

import (
	"regexp"

	"github.com/anchore/syft/internal"
)

const regexGroupExtractorKey = "Regex"

func regexGroupExtractor(pattern string) contentExtractor {
	pat := regexp.MustCompile(pattern)
	return func(contents []byte) map[string]string {
		return internal.MatchNamedCaptureGroups(pat, string(contents))
	}
}

const extractAllKey = "All"

func extractAll(extractor ...contentExtractor) contentExtractor {
	return func(contents []byte) map[string]string {
		for _, e := range extractor {
			out := e(contents)
			if out != nil {
				return out
			}
		}
		return nil
	}
}
