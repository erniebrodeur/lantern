package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:generated
var embedded embed.FS

// Handler serves the embedded production UI with an index fallback for client routes.
func Handler() http.Handler {
	assets, err := fs.Sub(embedded, "generated")
	if err != nil {
		panic(err)
	}
	return handlerFor(assets)
}

type spaHandler struct {
	assets fs.FS
	files  http.Handler
}

func handlerFor(assets fs.FS) http.Handler {
	return &spaHandler{assets: assets, files: http.FileServer(http.FS(assets))}
}

func (handler *spaHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/api" || strings.HasPrefix(request.URL.Path, "/api/") {
		http.NotFound(writer, request)
		return
	}
	if _, err := fs.Stat(handler.assets, "index.html"); err != nil {
		http.Error(writer, "Lantern UI is not embedded; build with `make build`", http.StatusServiceUnavailable)
		return
	}
	assetPath := strings.TrimPrefix(request.URL.Path, "/")
	if assetPath == "" {
		assetPath = "index.html"
	} else if info, err := fs.Stat(handler.assets, assetPath); err != nil || info.IsDir() {
		assetPath = "index.html"
	}
	clone := request.Clone(request.Context())
	urlCopy := *request.URL
	if assetPath == "index.html" {
		// FileServer serves index.html for a directory request; requesting the
		// file directly triggers its canonical redirect to ./.
		urlCopy.Path = "/"
	} else {
		urlCopy.Path = "/" + assetPath
	}
	clone.URL = &urlCopy
	handler.files.ServeHTTP(writer, clone)
}
