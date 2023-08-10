package derive

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
	lru "github.com/hashicorp/golang-lru/v2"
)

var (
	seenFtraceHooks *lru.Cache[string, uint64]
)

func init() {
	var err error
	seenFtraceHooks, err = lru.New[string, uint64](2048)
	if err != nil {
		panic(err)
	}
}

func FtraceHook() DeriveFunction {
	return deriveSingleEvent(events.FtraceHook, deriveFtraceHookArgs())
}

func deriveFtraceHookArgs() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		symbol, err := parse.ArgVal[string](event.Args, "symbol")
		if err != nil {
			return nil, err
		}

		flags, err := parse.ArgVal[uint64](event.Args, "flags")
		if err != nil {
			return nil, err
		}

		if prevFlags, found := seenFtraceHooks.Get(symbol); found {
			if prevFlags == flags {
				return nil, nil // event in cache: already reported.
			}
		}

		seenFtraceHooks.Add(symbol, flags)

		return []interface{}{symbol, flags}, nil
	}
}
