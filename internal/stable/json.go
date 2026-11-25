// Package stable provides deterministic JSON encoding used for reproducible
// reports and conclusion hashes.
package stable

import (
	"bytes"
	"encoding/json"
)

// JSON returns indented JSON with HTML escaping disabled and trailing newline.
// Struct field order is fixed by the type definition; callers must sort slices
// and avoid relying on map iteration. Maps are still emitted with sorted keys by
// encoding/json.
func JSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Compact returns canonical-ish compact JSON (no insignificant whitespace),
// suitable as input to a content hash.
func Compact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// json.Encoder.Encode appends a newline; drop exactly that trailing '\n'.
	b := buf.Bytes()
	return bytes.TrimSuffix(b, []byte("\n")), nil
}
