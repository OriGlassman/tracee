package derive

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
	lru "github.com/hashicorp/golang-lru/v2"
)

var (
	seenFtraceHooks *lru.Cache[string, []interface{}]
)

func init() {
	var err error
	seenFtraceHooks, err = lru.New[string, []interface{}](2048)
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

		callback, err := parse.ArgVal[string](event.Args, "callback")
		if err != nil {
			return nil, err
		}

		if argsFound, found := seenFtraceHooks.Get(symbol); found {
			prevFlags := argsFound[0].(uint64)
			prevCallback := argsFound[1].(string)

			if prevFlags == flags && prevCallback == callback {
				return nil, nil // event in cache: already reported.
			}
		}

		args := []interface{}{flags, callback}
		seenFtraceHooks.Add(symbol, args)

		return []interface{}{symbol, flags, callback}, nil
	}
}
