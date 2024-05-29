package regex

import (
	"bytes"
	"sync"
	"text/template"

	"github.com/anchore/syft/internal/log"
)

var parseMutex sync.Mutex
var parsed = map[string]func(args any) string{}

func execTemplate(tpl string, args any) string {
	var err error
	t := parsed[tpl]
	if t == nil {
		parseMutex.Lock()
		defer parseMutex.Unlock()
		t = parsed[tpl]
		if t == nil {
			tp := template.New("").Option("missingkey=zero")
			tp, err = tp.Parse(tpl)
			if err != nil {
				log.Debugf("unable to parse template '%s': %v", tpl, err)
				t = func(_ any) string {
					return tpl
				}
			} else {
				t = func(args any) string {
					buf := bytes.Buffer{}
					err = tp.Execute(&buf, args)
					if err != nil {
						log.Debugf("unable to execute template '%s': %v", tpl, err)
						return tpl
					}
					return buf.String()
				}
			}
			parsed[tpl] = t
		}
	}
	return t(args)
}
