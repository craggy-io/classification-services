// Package artifactsvc connects classification-services to Craggy
// artifact-services. It lives in its own module so the classification core
// stays dependency-free; import it only where both libraries meet.
//
// It provides three things:
//
//   - Classifier.ClassifyArtifact classifies every file of an immutable
//     artifact snapshot.
//   - Classifier.Publish stores the full report as an artifact, optionally
//     as two validated Objects tables (types and anomalies) that can be
//     queried with sql-v1, and optionally records a lineage activity linking
//     the input artifact to everything published.
//   - Observer bridges classification events into artifact-services
//     observability spans, so one collector sees both libraries' work.
package artifactsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/craggy-io/artifact-services/artifacts"
	"github.com/craggy-io/artifact-services/cas"
	"github.com/craggy-io/artifact-services/lineage"
	"github.com/craggy-io/artifact-services/objects"
	"github.com/craggy-io/artifact-services/provenance"

	"github.com/craggy-io/classification-services/classify"
)

// ReportVersion identifies the report and table formats.
const ReportVersion = "classification-report-v1"

// Classifier classifies artifacts and publishes the results. Engine,
// Artifacts and CAS are required; Objects and Lineage are optional.
type Classifier struct {
	Engine    *classify.Engine
	Artifacts artifacts.Store
	CAS       cas.Store
	Objects   *objects.Service // publish typed tables when set
	Lineage   lineage.Store    // record a lineage activity when set

	// MaxFileBytes bounds each file staged for classification (artifact
	// readers are streams; classification needs random access). Zero
	// selects 1 GiB.
	MaxFileBytes int64
	// TempDir stages files larger than 32 MiB; empty uses the OS default.
	TempDir string
	// Depth applies to every file (Standard by default). Per-call options
	// passed to ClassifyArtifact are applied after it.
	Depth classify.Depth
}

// FileResult is one classified artifact file.
type FileResult struct {
	Path    string           `json:"path"`
	Content cas.ID           `json:"content"`
	Size    int64            `json:"size"`
	Result  *classify.Result `json:"result,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// Report is the classification of one artifact snapshot.
type Report struct {
	Version  string         `json:"version"`
	Artifact artifacts.ID   `json:"artifact"`
	Engine   string         `json:"engine_revision"`
	Depth    classify.Depth `json:"depth"`
	Files    []FileResult   `json:"files"`
}

const inlineLimit = 32 << 20

// ClassifyArtifact classifies every file in the artifact, with each file's
// path as its name hint. Per-file failures
// are recorded in the report; the error is for failures to read the
// artifact itself.
func (c *Classifier) ClassifyArtifact(ctx context.Context, id artifacts.ID, opts ...classify.ClassifyOption) (*Report, error) {
	if c.Engine == nil || c.Artifacts == nil {
		return nil, errors.New("artifactsvc: Engine and Artifacts are required")
	}
	opts = append([]classify.ClassifyOption{classify.WithDepth(c.Depth)}, opts...)
	rep := &Report{Version: ReportVersion, Artifact: id, Engine: c.Engine.Revision(), Depth: classify.EffectiveDepth(c.Depth, opts[1:]...)}
	cursor := ""
	seenCursors := map[string]bool{}
	for {
		page, err := c.Artifacts.ListFiles(ctx, id, artifacts.FileQuery{Limit: 1000, Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("artifactsvc: listing %s: %w", id, err)
		}
		for _, e := range page.Entries {
			fr := FileResult{Path: e.Path, Content: e.Content, Size: e.Size}
			r, err := c.classifyFile(ctx, id, e, opts)
			if err != nil {
				fr.Error = err.Error()
			} else {
				fr.Result = r
			}
			rep.Files = append(rep.Files, fr)
		}
		if page.NextCursor == "" {
			return rep, nil
		}
		if seenCursors[page.NextCursor] {
			return nil, fmt.Errorf("artifactsvc: listing %s: cursor %q does not advance", id, page.NextCursor)
		}
		seenCursors[page.NextCursor] = true
		cursor = page.NextCursor
	}
}

func (c *Classifier) classifyFile(ctx context.Context, id artifacts.ID, e artifacts.Entry, opts []classify.ClassifyOption) (*classify.Result, error) {
	limit := c.MaxFileBytes
	if limit <= 0 {
		limit = 1 << 30
	}
	if e.Size > limit {
		return nil, fmt.Errorf("file of %d bytes exceeds MaxFileBytes", e.Size)
	}
	rc, err := c.Artifacts.OpenFile(ctx, id, e.Path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// Stage by actual bytes read, not the manifest's claim: buffer up to
	// inlineLimit, spill to a temp file past it, and read to EOF so the
	// CAS reader's integrity check and the size checks below are real.
	st := &staging{tempDir: c.TempDir}
	n, err := io.Copy(st, io.LimitReader(rc, limit+1))
	if err != nil {
		st.cleanup()
		return nil, err
	}
	defer st.cleanup()
	// Integrity is established at EOF by the CAS reader: close before use.
	if err := rc.Close(); err != nil {
		return nil, fmt.Errorf("verifying %s: %w", e.Path, err)
	}
	if n > limit {
		return nil, fmt.Errorf("file of more than %d bytes exceeds MaxFileBytes", limit)
	}
	if n != e.Size {
		return nil, fmt.Errorf("manifest size %d does not match %d bytes read", e.Size, n)
	}
	var src classify.Source
	if st.file != nil {
		src = classify.ReaderAt(st.file, n)
	} else {
		src = classify.Bytes(st.buf.Bytes())
	}
	return c.Engine.Classify(ctx, src.Named(e.Path), opts...)
}

// staging buffers a stream in memory up to inlineLimit, then spills to a
// temp file.
type staging struct {
	tempDir string
	buf     bytes.Buffer
	file    *os.File
}

func (s *staging) Write(p []byte) (int, error) {
	if s.file == nil && int64(s.buf.Len())+int64(len(p)) > inlineLimit {
		f, err := os.CreateTemp(s.tempDir, "artifactsvc-*")
		if err != nil {
			return 0, err
		}
		if _, err := f.Write(s.buf.Bytes()); err != nil {
			f.Close()
			os.Remove(f.Name())
			return 0, err
		}
		s.buf.Reset()
		s.file = f
	}
	if s.file != nil {
		return s.file.Write(p)
	}
	return s.buf.Write(p)
}

func (s *staging) cleanup() {
	if s.file != nil {
		s.file.Close()
		os.Remove(s.file.Name())
		s.file = nil
	}
}

// Published lists what Publish stored.
type Published struct {
	Report    artifacts.ID `json:"report"`
	Types     artifacts.ID `json:"types,omitempty"`     // typed table (Objects)
	Anomalies artifacts.ID `json:"anomalies,omitempty"` // typed table (Objects)
	Activity  lineage.ID   `json:"activity,omitempty"`
	// TypesRevision and AnomaliesRevision are lineage revisions of the
	// tables, recorded with the activity; pin them in Objects queries.
	TypesRevision     lineage.ID `json:"types_revision,omitempty"`
	AnomaliesRevision lineage.ID `json:"anomalies_revision,omitempty"`
}

// Publish stores the report and, when configured, the typed tables and the
// lineage activity. Each stage is a separate commitment: on error, the
// returned Published lists what was already stored.
func (c *Classifier) Publish(ctx context.Context, rep *Report) (Published, error) {
	var out Published
	if rep == nil {
		return out, errors.New("artifactsvc: nil report")
	}
	if c.CAS == nil || c.Artifacts == nil {
		return out, errors.New("artifactsvc: CAS and Artifacts are required to publish")
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return out, err
	}
	if out.Report, err = c.file(ctx, "classification.json", body, "classification-report"); err != nil {
		return out, fmt.Errorf("artifactsvc: publishing report: %w", err)
	}
	if c.Objects != nil {
		if out.Types, err = c.table(ctx, typesSchema(), typeRows(rep), "classification-types"); err != nil {
			return out, fmt.Errorf("artifactsvc: publishing types table: %w", err)
		}
		if out.Anomalies, err = c.table(ctx, anomaliesSchema(), anomalyRows(rep), "classification-anomalies"); err != nil {
			return out, fmt.Errorf("artifactsvc: publishing anomalies table: %w", err)
		}
	}
	if c.Lineage != nil {
		outputs := []provenance.Ref{{Artifact: string(out.Report)}}
		for _, t := range []artifacts.ID{out.Types, out.Anomalies} {
			if t != "" {
				outputs = append(outputs, provenance.Ref{Artifact: string(t)})
			}
		}
		md := map[string]json.RawMessage{}
		md["engine_revision"], _ = json.Marshal(rep.Engine)
		md["depth"], _ = json.Marshal(rep.Depth)
		md["report_version"], _ = json.Marshal(rep.Version)
		// The ID is deterministic, so re-publishing the same classification
		// is an idempotent retry rather than a second activity.
		id := lineage.ID(fmt.Sprintf("classification:%s:%s:%s", rep.Artifact, rep.Engine, rep.Depth))
		rec := lineage.Record{ID: id, Activity: &lineage.Activity{
			Kind: "classification", Actor: "classification-services",
			Inputs: []provenance.Ref{{Artifact: string(rep.Artifact)}}, Outputs: outputs, Metadata: md,
		}}
		if out.Activity, err = c.Lineage.Record(ctx, rec); err != nil {
			return out, fmt.Errorf("artifactsvc: recording lineage: %w", err)
		}
		for _, t := range []struct {
			artifact artifacts.ID
			dst      *lineage.ID
		}{{out.Types, &out.TypesRevision}, {out.Anomalies, &out.AnomaliesRevision}} {
			if t.artifact == "" {
				continue
			}
			rev := lineage.Record{ID: lineage.ID("revision:" + string(t.artifact)), Revision: &lineage.Revision{Artifact: t.artifact, Activity: out.Activity}}
			if *t.dst, err = c.Lineage.Record(ctx, rev); err != nil {
				return out, fmt.Errorf("artifactsvc: recording table revision: %w", err)
			}
		}
	}
	return out, nil
}

func (c *Classifier) file(ctx context.Context, path string, data []byte, kind string) (artifacts.ID, error) {
	put, err := c.CAS.Put(ctx, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	k, _ := json.Marshal(kind)
	return c.Artifacts.Publish(ctx, artifacts.Manifest{
		Version:  1,
		Entries:  []artifacts.Entry{{Path: path, Content: put.ID, Size: put.Size}},
		Metadata: map[string]json.RawMessage{"kind": k},
	})
}

func (c *Classifier) table(ctx context.Context, schema objects.SchemaDefinition, rows []objects.Row, kind string) (artifacts.ID, error) {
	sid, err := c.Objects.DefineSchema(ctx, schema)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			return "", err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	raw, err := c.file(ctx, "rows.ndjson", buf.Bytes(), kind+"-source")
	if err != nil {
		return "", err
	}
	k, _ := json.Marshal(kind)
	return c.Objects.Publish(ctx, objects.PublishRequest{
		ValidationRequest: objects.ValidationRequest{Data: raw, Schema: sid, Encoding: objects.NDJSON},
		Metadata:          map[string]json.RawMessage{"kind": k},
	})
}

func col(id string, typ string) objects.Column {
	return objects.Column{ID: id, Name: id, Shape: objects.Shape{Type: typ}}
}

// typesSchema: one row per (file, matched type) at the top level.
func typesSchema() objects.SchemaDefinition {
	return objects.SchemaDefinition{Version: objects.SchemaVersion, Model: objects.Table, Columns: []objects.Column{
		col("path", "string"), col("digest", "string"), col("type", "string"), col("level", "string"),
		col("direct", "boolean"), col("primary", "boolean"),
	}}
}

// anomaliesSchema: one row per anomaly anywhere in each file's DAG.
func anomaliesSchema() objects.SchemaDefinition {
	return objects.SchemaDefinition{Version: objects.SchemaVersion, Model: objects.Table, Columns: []objects.Column{
		col("path", "string"), col("node", "string"), col("code", "string"), col("severity", "string"),
		col("by", "string"), col("message", "string"),
	}}
}

func typeRows(rep *Report) []objects.Row {
	var rows []objects.Row
	for fi, f := range rep.Files {
		if f.Result == nil {
			continue
		}
		for mi, m := range f.Result.Matches {
			rows = append(rows, objects.Row{ID: fmt.Sprintf("f%d-t%d", fi, mi), Values: map[string]any{
				"path": f.Path, "digest": f.Result.Digest, "type": m.Type, "level": m.Level.String(),
				"direct": m.Direct, "primary": m.Type == f.Result.Primary,
			}})
		}
	}
	return rows
}

func anomalyRows(rep *Report) []objects.Row {
	var rows []objects.Row
	for fi, f := range rep.Files {
		if f.Result == nil {
			continue
		}
		n := 0
		// Per-path traversal (not Result.Walk, which dedups shared nodes):
		// an anomaly on a digest-shared child is one row per path to it.
		var visit func(r *classify.Result, node string, ancestors map[*classify.Result]bool)
		visit = func(r *classify.Result, node string, ancestors map[*classify.Result]bool) {
			if r == nil || ancestors[r] {
				return
			}
			ancestors[r] = true
			defer delete(ancestors, r)
			for _, a := range r.Anomalies {
				rows = append(rows, objects.Row{ID: fmt.Sprintf("f%d-a%d", fi, n), Values: map[string]any{
					"path": f.Path, "node": node, "code": a.Code, "severity": a.Severity.String(),
					"by": a.By, "message": a.Message,
				}})
				n++
			}
			for _, ch := range r.Children {
				child := ch.Name
				if node != "" {
					child = node + "/" + ch.Name
				}
				visit(ch.Result, child, ancestors)
			}
		}
		visit(f.Result, "", map[*classify.Result]bool{})
	}
	return rows
}
