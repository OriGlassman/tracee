package derive

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
	"github.com/aquasecurity/tracee/types/trace"
	lru "github.com/hashicorp/golang-lru/v2"
)

type entry struct {
	packageName string
	containerId string
}

var cache *lru.Cache[entry, struct{}]

func init() {
	var err error
	cache, err = lru.New[entry, struct{}](2048)
	if err != nil {
		panic(err)
	}
}

func DetectPackageLoaded(kernelSymbols *environment.KernelSymbolTable) DeriveFunction {
	return deriveSingleEvent(events.PackageLoaded, derivePackageLoadedArgs(kernelSymbols))
}

func derivePackageLoadedArgs(kernelSymbols *environment.KernelSymbolTable) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		packageName, err := parse.ArgVal[string](event.Args, "package_name")
		if err != nil {
			return nil, errfmt.Errorf("error parsing syscall_id arg: %v", err)
		}

		e := entry{
			packageName: packageName,
			containerId: event.ContainerID,
		}

		if contains := cache.Contains(e); contains {
			return nil, nil
		}

		cache.Add(e, struct{}{})

		path, err := parse.ArgVal[string](event.Args, "pathname")
		if err != nil {
			return nil, errfmt.Errorf("error parsing syscall_id arg: %v", err)
		}

		//logger.Infow("", "package", packageName, "containerid", event.ContainerID, "path", path)

		return []interface{}{path, packageName}, nil
	}
}
