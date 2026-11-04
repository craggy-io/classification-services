package probes

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

func compact(s string) string { return strings.Join(strings.Fields(s), "") }

// base64Candidate applies the shared heuristics: base64 may be line-wrapped
// but is never space-separated prose, and short strings are too ambiguous.
func base64Candidate(text string) (string, bool) {
	t := strings.TrimSpace(text)
	if strings.Contains(t, " ") {
		return "", false
	}
	s := compact(t)
	return s, len(s) >= 20
}

func decodeBase64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict(),
		base64.URLEncoding.Strict(), base64.RawURLEncoding.Strict(),
	} {
		if out, err := enc.DecodeString(s); err == nil && len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

// Base64 recognises base64-encoded text.
func Base64(_ context.Context, in Input) ([]Finding, error) {
	text, err := in.Text(in.Limits().MaxBytes)
	if err != nil {
		return nil, err
	}
	s, ok := base64Candidate(text)
	if !ok {
		return nil, nil
	}
	if _, ok := decodeBase64(s); !ok {
		return nil, nil
	}
	return []Finding{Match("encoding.base64", Recognised, map[string]any{"length": len(s)})}, nil
}

// Base64Decode derives the speculative base64 decoding.
func Base64Decode(_ context.Context, in Input) ([]Finding, error) {
	text, err := in.Text(in.Limits().MaxBytes)
	if err != nil {
		return nil, err
	}
	s, ok := base64Candidate(text)
	if !ok {
		return nil, nil
	}
	out, ok := decodeBase64(s)
	if !ok {
		return nil, nil
	}
	return []Finding{{Children: []Derived{{Name: "base64", Data: out, Speculative: true}}}}, nil
}

func hexCandidate(text string) string {
	return strings.TrimPrefix(strings.ToLower(compact(text)), "0x")
}

// Hex recognises hex-encoded text of at least 16 bytes.
func Hex(_ context.Context, in Input) ([]Finding, error) {
	text, err := in.Text(in.Limits().MaxBytes)
	if err != nil {
		return nil, err
	}
	s := hexCandidate(text)
	if len(s) < 32 || len(s)%2 != 0 {
		return nil, nil
	}
	if _, err := hex.DecodeString(s); err != nil {
		return nil, nil
	}
	return []Finding{Match("encoding.hex", Recognised, map[string]any{"length": len(s)})}, nil
}

// HexDecode derives the speculative hex decoding.
func HexDecode(_ context.Context, in Input) ([]Finding, error) {
	text, err := in.Text(in.Limits().MaxBytes)
	if err != nil {
		return nil, err
	}
	out, err := hex.DecodeString(hexCandidate(text))
	if err != nil {
		return nil, nil
	}
	return []Finding{{Children: []Derived{{Name: "hex", Data: out, Speculative: true}}}}, nil
}

var digestAlgorithms = map[int]string{32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}

// Digest recognises text that is exactly one hexadecimal digest of a
// standard length.
func Digest(_ context.Context, in Input) ([]Finding, error) {
	if in.Size() > 160 {
		return nil, nil
	}
	text, err := in.Text(160)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(text)
	alg, ok := digestAlgorithms[len(s)]
	if !ok {
		return nil, nil
	}
	if _, err := hex.DecodeString(s); err != nil {
		return nil, nil
	}
	return []Finding{Match("crypto.digest", Validated, map[string]any{"length": len(s), "algorithm_guess": alg})}, nil
}
