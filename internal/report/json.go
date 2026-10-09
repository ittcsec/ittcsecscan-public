package report

import "encoding/json"

// JSON renders the frozen report model as indented JSON, the authoritative machine
// format. It is a pure serialization of the model: coverage precedes findings by the
// model's field order, and every string is already sanitized. Deterministic.
func JSON(r Report) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
