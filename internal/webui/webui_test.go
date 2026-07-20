package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestHandlerServesAssetsAndFallsBackToIndex(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<main>Lantern</main>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('lantern')")},
	}
	handler := handlerFor(assets)
	for _, test := range []struct {
		path        string
		wantStatus  int
		wantContent string
	}{
		{path: "/", wantStatus: http.StatusOK, wantContent: "<main>Lantern</main>"},
		{path: "/host/192.0.2.1", wantStatus: http.StatusOK, wantContent: "<main>Lantern</main>"},
		{path: "/assets/app.js", wantStatus: http.StatusOK, wantContent: "console.log('lantern')"},
		{path: "/api/missing", wantStatus: http.StatusNotFound, wantContent: "404 page not found\n"},
	} {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || response.Body.String() != test.wantContent {
				t.Fatalf("%s returned %d %q", test.path, response.Code, response.Body.String())
			}
		})
	}
}

func TestHandlerReportsMissingGeneratedUI(t *testing.T) {
	handler := handlerFor(fstest.MapFS{".placeholder": &fstest.MapFile{Data: []byte("placeholder")}})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing UI returned %d", response.Code)
	}
}
