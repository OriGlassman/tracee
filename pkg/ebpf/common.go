package ebpf

import "time"
import "math/rand"

// generateRandomDuration returns a random duration between min and max, inclusive
func generateRandomDuration(min, max int) time.Duration {
	return time.Duration(rand.Intn(max-min+1)+min) * time.Second
}
