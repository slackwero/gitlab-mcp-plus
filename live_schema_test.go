//go:build live

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	// minLiveDocuments guards against a discovery that silently finds nothing.
	minLiveDocuments = 20
	// liveSchemaBatchChars caps the query text of one request: GitLab answers
	// larger ones with 422 "Query too large".
	liveSchemaBatchChars = 9000
	// liveTimeout bounds each request the test sends to GitLab.
	liveTimeout = 60 * time.Second
	// maxBodyInFailure keeps an unexpected response readable in the output.
	maxBodyInFailure = 2000
)

// liveDocument is a GraphQL document to validate against the real schema.
type liveDocument struct {
	name  string // constant name, plus "/project" or "/group" for templates
	query string
}

// liveResult is GitLab's answer to one document of a multiplexed request.
type liveResult struct {
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

// TestLiveSchema validates every GraphQL document of the server against the
// real GitLab schema. The documents travel without a token and without
// variables in a few multiplexed requests, each under GitLab's query size
// limit: GitLab validates each document statically and reports an unknown
// field or argument with extensions.code, while a missing required variable
// aborts the operation before anything executes. Each batch is sent exactly
// once and the first failure stops the run, so the test stays within the
// per-IP limit for unauthenticated traffic and never becomes a request loop.
func TestLiveSchema(t *testing.T) {
	docs := discoverDocuments(t)
	if len(docs) < minLiveDocuments {
		t.Fatalf("discovered %d documents, want at least %d: discovery is broken", len(docs), minLiveDocuments)
	}
	batches, err := batchDocuments(docs, liveSchemaBatchChars)
	if err != nil {
		t.Fatal(err)
	}

	endpoint := liveBaseURL() + "/api/graphql"
	results := make([]*liveResult, 0, len(docs))
	for n, batch := range batches {
		got := sendBatch(t, endpoint, batch, n+1, len(batches))
		if len(got) != len(batch) {
			t.Errorf("batch %d: GitLab sent %d results for %d documents", n+1, len(got), len(batch))
		}
		for i := range batch {
			if i < len(got) {
				results = append(results, &got[i])
			} else {
				results = append(results, nil)
			}
		}
	}
	t.Logf("sent %d documents to %s in %d requests", len(docs), endpoint, len(batches))

	for i, doc := range docs {
		t.Run(doc.name, func(t *testing.T) {
			if results[i] == nil {
				t.Fatal("GitLab sent no result for this document")
			}
			for _, e := range results[i].Errors {
				if e.Extensions.Code != "" {
					t.Errorf("%s: %s", e.Extensions.Code, e.Message)
				}
			}
		})
	}
}

func TestLiveSchema_Batches(t *testing.T) {
	doc := func(name string, size int) liveDocument {
		return liveDocument{name: name, query: strings.Repeat("x", size)}
	}
	batches, err := batchDocuments([]liveDocument{doc("a", 4), doc("b", 5), doc("c", 2), doc("d", 10)}, 10)
	if err != nil {
		t.Fatalf("batchDocuments: %v", err)
	}
	var got [][]string
	for _, batch := range batches {
		var names []string
		for _, d := range batch {
			names = append(names, d.name)
		}
		got = append(got, names)
	}
	// In order, greedily, and a document exactly at the limit fits alone.
	if want := [][]string{{"a", "b"}, {"c"}, {"d"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("batches = %v, want %v", got, want)
	}

	if _, err := batchDocuments([]liveDocument{doc("a", 3), doc("huge", 11)}, 10); err == nil ||
		!strings.Contains(err.Error(), "huge") {
		t.Errorf("a document over the limit must fail naming it, err = %v", err)
	}
}

func liveBaseURL() string {
	if base := os.Getenv("GITLAB_URL"); base != "" {
		return base
	}
	return "https://gitlab.com"
}

// discoverDocuments parses the non-test Go files of the package and returns
// every constant named query… or mutation… whose value is a single string
// literal. Templates with __SCOPE__ yield a project and a group document.
func discoverDocuments(t *testing.T) []liveDocument {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing the Go files: %v", err)
	}

	fset := token.NewFileSet()
	var docs []liveDocument
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				docs = append(docs, documentsIn(t, spec.(*ast.ValueSpec))...)
			}
		}
	}
	return docs
}

func documentsIn(t *testing.T, spec *ast.ValueSpec) []liveDocument {
	t.Helper()
	var docs []liveDocument
	for i, ident := range spec.Names {
		name := ident.Name
		if !isDocumentName(name) || i >= len(spec.Values) {
			continue
		}
		lit, ok := spec.Values[i].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		query, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("unquoting %s: %v", name, err)
		}
		if !strings.Contains(query, scopePlaceholder) {
			docs = append(docs, liveDocument{name: name, query: query})
			continue
		}
		for _, scope := range []string{"project", "group"} {
			docs = append(docs, liveDocument{name: name + "/" + scope, query: scopedQuery(query, scope)})
		}
	}
	return docs
}

func isDocumentName(name string) bool {
	return strings.HasPrefix(name, "query") || strings.HasPrefix(name, "mutation")
}

// batchDocuments groups the documents greedily, in order, so that the query
// text of each batch adds up to at most limit characters. A document longer
// than limit is an error: GitLab would reject any request carrying it.
func batchDocuments(docs []liveDocument, limit int) ([][]liveDocument, error) {
	var batches [][]liveDocument
	var current []liveDocument
	size := 0
	for _, doc := range docs {
		n := utf8.RuneCountInString(doc.query)
		if n > limit {
			return nil, fmt.Errorf("%s has %d characters, more than the %d one request may carry: it can never be validated",
				doc.name, n, limit)
		}
		if size+n > limit {
			batches = append(batches, current)
			current, size = nil, 0
		}
		current = append(current, doc)
		size += n
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches, nil
}

// sendBatch posts the documents of one batch as a JSON array, without a token
// and without variables, and returns GitLab's results in the same order. Any
// answer other than 200 stops the test: nothing is retried.
func sendBatch(t *testing.T, endpoint string, batch []liveDocument, n, total int) []liveResult {
	t.Helper()
	body := make([]map[string]string, len(batch))
	for i, doc := range batch {
		body[i] = map[string]string{"query": doc.query}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling batch %d: %v", n, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), liveTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("creating the request for batch %d: %v", n, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sending batch %d of %d: %v", n, total, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response to batch %d: %v", n, err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GitLab answered %d to batch %d of %d (Retry-After: %q): %s. No further batches were sent; do not retry in a loop",
			resp.StatusCode, n, total, resp.Header.Get("Retry-After"), truncated(raw))
	}
	var results []liveResult
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatalf("GitLab did not answer batch %d with one result per document (%v): %s", n, err, truncated(raw))
	}
	return results
}

func truncated(body []byte) string {
	if len(body) <= maxBodyInFailure {
		return string(body)
	}
	return string(body[:maxBodyInFailure]) + "…"
}
