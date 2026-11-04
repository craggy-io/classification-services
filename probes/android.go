package probes

import (
	"bytes"
	"context"
	"strings"

	"github.com/craggy-io/classification-services/evidence"
	"github.com/craggy-io/classification-services/views"
)

// APK recognises Android packages, split-APK sets and app bundles inside a
// ZIP. For packages it parses the binary manifest and the APK Signing Block
// and reports debuggable builds and weak or missing signatures.
func APK(_ context.Context, in Input) ([]Finding, error) {
	z, err := view[*views.Zip](in, "zip")
	if err != nil {
		return nil, nil
	}
	var out []Finding
	dex, apks := 0, 0
	v1 := false
	for _, f := range z.Files {
		lower := strings.ToLower(f.Name)
		switch {
		case strings.HasSuffix(lower, ".dex") && !strings.Contains(f.Name, "/"):
			dex++
		case strings.HasSuffix(lower, ".apk"):
			apks++
		case strings.HasPrefix(f.Name, "META-INF/") && (strings.HasSuffix(lower, ".rsa") || strings.HasSuffix(lower, ".dsa") || strings.HasSuffix(lower, ".ec")):
			v1 = true
		}
	}
	switch {
	case z.Has("AndroidManifest.xml"):
		md := map[string]any{"entry_count": len(z.Files), "dex_count": dex, "resources": z.Has("resources.arsc")}
		level := Recognised
		if dex > 0 || z.Has("resources.arsc") {
			level = Validated
		}
		f := Match("android.apk", level, md)
		if raw, err := z.Read("AndroidManifest.xml", 8<<20); err == nil {
			if doc, err := views.ParseAXML(raw); err == nil {
				if m, err := doc.Manifest(); err == nil {
					md["package"], md["version_code"], md["version_name"] = m.Package, m.VersionCode, m.VersionName
					md["min_sdk"], md["target_sdk"] = m.MinSDK, m.TargetSDK
					md["permissions"] = first(m.Permissions, 200)
					md["exported_components"] = first(m.Exported, 200)
					md["debuggable"] = m.Debuggable
					level = Validated
					f.Level = level
					if m.Debuggable {
						f.Anomalies = append(f.Anomalies, evidence.Anomaly{
							Code: "android.debuggable", Severity: evidence.Warning,
							Message: "the application is built with android:debuggable=true",
						})
					}
				}
			} else {
				f.Anomalies = append(f.Anomalies, evidence.Anomaly{
					Code: "android.manifest-unparsed", Severity: evidence.Info,
					Message: "AndroidManifest.xml is not valid binary XML: " + err.Error(),
				})
			}
		}
		var schemes []string
		if v1 {
			schemes = append(schemes, "v1")
		}
		if b, err := view[*views.APKSigningBlock](in, "apk-signing-block"); err == nil {
			schemes = append(schemes, b.Schemes...)
		}
		md["signature_schemes"] = schemes
		switch {
		case len(schemes) == 0:
			f.Anomalies = append(f.Anomalies, evidence.Anomaly{
				Code: "android.unsigned", Severity: evidence.Warning,
				Message: "no v1 signature files and no APK Signing Block",
			})
		case len(schemes) == 1 && schemes[0] == "v1":
			f.Anomalies = append(f.Anomalies, evidence.Anomaly{
				Code: "android.v1-signature-only", Severity: evidence.Info,
				Message: "signed only with the JAR (v1) scheme, which does not cover the whole file",
			})
		}
		out = append(out, f)
	case apks > 0:
		out = append(out, Match("android.apk-set", Validated, map[string]any{"apk_count": apks, "entry_count": len(z.Files)}))
	}
	if z.Has("BundleConfig.pb") {
		out = append(out, Match("android.aab", Validated, map[string]any{"base_manifest": z.Has("base/manifest/AndroidManifest.xml")}))
	}
	return out, nil
}

// Dex validates a Dalvik Executable header.
func Dex(_ context.Context, in Input) ([]Finding, error) {
	d, err := view[*views.Dex](in, "dex")
	if err != nil {
		head, _ := in.Prefix(4)
		if bytes.Equal(head, []byte("dex\n")) {
			return []Finding{Reject("android.dex", Validated)}, nil
		}
		return nil, nil
	}
	md := map[string]any{}
	for k, v := range d.Describe() {
		md[k] = v
	}
	return []Finding{Match("android.dex", Validated, md)}, nil
}

// AXML recognises a standalone Android binary XML document (for example a
// manifest extracted from an APK).
func AXML(_ context.Context, in Input) ([]Finding, error) {
	head, err := in.Prefix(8)
	if err != nil || len(head) < 8 || head[0] != 0x03 || head[1] != 0x00 || head[2] != 0x08 || head[3] != 0x00 {
		return nil, err
	}
	doc, err := view[*views.AXML](in, "axml")
	if err != nil {
		return []Finding{Reject("android.axml", Validated)}, nil
	}
	return []Finding{Match("android.axml", Validated, doc.Describe())}, nil
}
