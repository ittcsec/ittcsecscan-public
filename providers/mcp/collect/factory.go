package collect

import "github.com/ittcsec/ittcsecscan/internal/collect"

// Collectors builds the MCP read-only collector set for one scan, reading the given config
// file path with the injected file reader.
func Collectors(path string, readFile func(string) ([]byte, error), budget *collect.Budget) []collect.Collector {
	return []collect.Collector{
		NewServersCollector(path, readFile, budget),
	}
}
