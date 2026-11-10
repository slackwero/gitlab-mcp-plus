package gitlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient_RejectsOversizedResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"filler":"` + strings.Repeat("x", 200) + `"}}`))
	}))
	t.Cleanup(srv.Close)

	app := NewClient("test-token", srv.URL)
	app.maxResponseBytes = 100
	if _, err := app.GraphQL(context.Background(), "query { x }", nil); err == nil || !strings.Contains(err.Error(), "larger than 100 bytes") {
		t.Errorf("graphql error = %v", err)
	}
	if _, err := app.REST(context.Background(), "GET", "/x", nil); err == nil || !strings.Contains(err.Error(), "larger than 100 bytes") {
		t.Errorf("rest error = %v", err)
	}
	if _, _, err := app.RESTList(context.Background(), "/x"); err == nil || !strings.Contains(err.Error(), "larger than 100 bytes") {
		t.Errorf("restList error = %v", err)
	}
}
