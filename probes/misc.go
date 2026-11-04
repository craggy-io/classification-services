package probes

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"strings"
	"time"

	"github.com/craggy-io/classification-services/evidence"
	"github.com/craggy-io/classification-services/views"
)

var pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}

// PNG validates the signature and IHDR chunk (length, type and CRC).
func PNG(_ context.Context, in Input) ([]Finding, error) {
	b, err := in.Prefix(33)
	if err != nil {
		return nil, err
	}
	if len(b) < 33 || !bytes.Equal(b[:8], pngSignature) {
		return nil, nil
	}
	be := binary.BigEndian
	if be.Uint32(b[8:]) != 13 || string(b[12:16]) != "IHDR" || crc32.ChecksumIEEE(b[12:29]) != be.Uint32(b[29:]) {
		return []Finding{Reject("image.png", Validated)}, nil
	}
	return []Finding{Match("image.png", Validated, map[string]any{
		"width": int64(be.Uint32(b[16:])), "height": int64(be.Uint32(b[20:])),
		"bit_depth": int(b[24]), "color_type": int(b[25]),
	})}, nil
}

// Pcap validates classic pcap and pcapng captures.
func Pcap(_ context.Context, in Input) ([]Finding, error) {
	p, err := view[*views.Pcap](in, "pcap")
	if err != nil {
		return nil, nil
	}
	t := "network.pcap"
	if p.Format == "pcapng" {
		t = "network.pcapng"
	}
	return []Finding{Match(t, Validated, p.Describe())}, nil
}

const maxPEMBlocks = 64

// PEM recognises PEM-armoured text, validates certificates inside it,
// reports private keys and derives each block's DER bytes.
func PEM(_ context.Context, in Input) ([]Finding, error) {
	text, err := in.Text(min(in.Limits().MaxBytes, 4<<20))
	if err != nil || !strings.Contains(text, "-----BEGIN ") {
		return nil, err
	}
	rest := []byte(text)
	var kinds []string
	var certs []map[string]any
	pemF := Finding{}
	var out []Finding
	privateKey := false
	for i := 0; i < maxPEMBlocks; i++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		kinds = append(kinds, block.Type)
		if int64(len(block.Bytes)) <= in.Limits().MaxDerivedBytes {
			pemF.Children = append(pemF.Children, Derived{Name: fmt.Sprintf("pem[%d] %s", i, block.Type), Data: block.Bytes})
		}
		switch {
		case block.Type == "CERTIFICATE":
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				certs = append(certs, certSummary(c))
			}
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			privateKey = true
		}
	}
	if len(kinds) == 0 {
		return nil, nil
	}
	pemF.Type, pemF.Level = "crypto.pem", Validated
	pemF.Metadata = map[string]any{"blocks": kinds}
	out = append(out, pemF)
	if len(certs) > 0 {
		out = append(out, Match("crypto.x509", Validated, map[string]any{"certificates": len(certs), "first": certs[0]}))
	}
	if privateKey {
		k := Match("crypto.private-key", Validated, nil)
		k.Anomalies = []evidence.Anomaly{{
			Code: "crypto.private-key", Severity: evidence.Warning,
			Message: "the content contains private key material",
		}}
		out = append(out, k)
	}
	return out, nil
}

func certSummary(c *x509.Certificate) map[string]any {
	return map[string]any{
		"subject": c.Subject.String(), "issuer": c.Issuer.String(),
		"not_before": c.NotBefore.UTC().Format(time.RFC3339), "not_after": c.NotAfter.UTC().Format(time.RFC3339),
		"self_signed": bytes.Equal(c.RawSubject, c.RawIssuer), "is_ca": c.IsCA,
		"serial": c.SerialNumber.String(), "signature_algorithm": c.SignatureAlgorithm.String(),
	}
}

// DERCertificate validates a binary (DER) X.509 certificate. The validity
// period is reported as metadata, not judged against the current time, so
// results stay deterministic and cacheable.
func DERCertificate(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(2)
	if err != nil || len(head) < 2 || head[0] != 0x30 || head[1] < 0x80 || in.Size() > 1<<20 {
		return nil, err
	}
	b, err := in.Read(0, in.Size())
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, nil
	}
	return []Finding{Match("crypto.x509", Validated, certSummary(c))}, nil
}

// JWT recognises a JSON Web Token: three base64url segments whose header
// decodes to JSON with an "alg". Unsigned ("alg": "none") tokens are
// reported.
func JWT(_ context.Context, in Input) ([]Finding, error) {
	if in.Size() > 64<<10 {
		return nil, nil
	}
	text, err := in.Text(64 << 10)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimSpace(text), ".")
	if len(parts) != 3 || len(parts[0]) < 10 {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil
	}
	var hdr map[string]any
	if json.Unmarshal(raw, &hdr) != nil {
		return nil, nil
	}
	alg, ok := hdr["alg"].(string)
	if !ok {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !json.Valid(payload) {
		return nil, nil
	}
	if parts[2] != "" {
		if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
			return nil, nil
		}
	}
	md := map[string]any{"alg": alg}
	if typ, ok := hdr["typ"].(string); ok {
		md["typ"] = typ
	}
	f := Match("crypto.jwt", Validated, md)
	if strings.EqualFold(alg, "none") || parts[2] == "" {
		f.Anomalies = []evidence.Anomaly{{
			Code: "crypto.jwt-unsigned", Severity: evidence.Warning,
			Message: `the token is unsigned ("alg": "none" or an empty signature)`,
		}}
	}
	return []Finding{f}, nil
}
