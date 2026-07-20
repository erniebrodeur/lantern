package httpapi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
	"github.com/erniebrodeur/lantern/internal/scans"
	"github.com/erniebrodeur/lantern/internal/version"
	"github.com/erniebrodeur/lantern/internal/webui"
	"github.com/gin-contrib/sse"
	"github.com/gin-gonic/gin"
)

// API exposes scan management over Lantern's loopback-only HTTP interface.
type API struct {
	manager *scans.Manager
}

// NewRouter constructs the API and embedded-UI router for manager.
func NewRouter(manager *scans.Manager) (*gin.Engine, error) {
	router := gin.New()
	router.Use(loopbackHostOnly(), gin.Logger(), gin.Recovery())
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, err
	}
	api := &API{manager: manager}
	routes := router.Group("/api")
	routes.GET("/health", api.health)
	routes.GET("/capabilities", api.capabilities)
	routes.POST("/capabilities/refresh", api.refreshCapabilities)
	routes.GET("/profiles", api.listProfiles)
	routes.POST("/profiles", api.createProfile)
	routes.PUT("/profiles/:id", api.updateProfile)
	routes.DELETE("/profiles/:id", api.deleteProfile)
	routes.GET("/scans", api.listScans)
	routes.POST("/scans", api.startScan)
	routes.GET("/scans/events", api.allScanEvents)
	routes.GET("/scans/:id", api.getScan)
	routes.DELETE("/scans/:id", api.deleteScan)
	routes.GET("/scans/:id/hosts", api.listHosts)
	routes.GET("/scans/:id/hosts/:hostID", api.getHost)
	routes.GET("/scans/:id/evidence", api.listEvidence)
	routes.GET("/scans/:id/tools", api.listTools)
	routes.GET("/scans/:id/routes", api.savedRoutes)
	routes.POST("/scans/:id/routes", api.mapRoutes)
	routes.GET("/scans/:id/events", api.scanEvents)
	routes.POST("/scans/:id/cancel", api.cancelScan)
	router.NoRoute(gin.WrapH(webui.Handler()))
	return router, nil
}

func loopbackHostOnly() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		host := ctx.Request.Host
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Lantern only accepts local requests"})
			return
		}
		ctx.Next()
	}
}

func (a *API) health(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "version": version.Value})
}

func (a *API) capabilities(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, a.manager.Capabilities())
}

func (a *API) refreshCapabilities(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, a.manager.RefreshProviders(ctx.Request.Context()))
}

func (a *API) listProfiles(ctx *gin.Context) {
	profiles, err := a.manager.Profiles(ctx.Request.Context())
	if err != nil {
		writeError(ctx, http.StatusInternalServerError, err.Error())
		return
	}
	ctx.JSON(http.StatusOK, profiles)
}

func (a *API) createProfile(ctx *gin.Context) {
	a.saveProfile(ctx, "")
}

func (a *API) updateProfile(ctx *gin.Context) {
	a.saveProfile(ctx, ctx.Param("id"))
}

func (a *API) saveProfile(ctx *gin.Context, identifier string) {
	var request struct {
		ArgumentText string `json:"argumentText" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&request); err != nil {
		writeError(ctx, http.StatusBadRequest, "scan arguments are required")
		return
	}
	profile, err := a.manager.SaveProfile(ctx.Request.Context(), identifier, request.ArgumentText)
	if err != nil {
		if scans.IsNotFound(err) {
			writeError(ctx, http.StatusNotFound, err.Error())
		} else {
			writeError(ctx, http.StatusBadRequest, err.Error())
		}
		return
	}
	status := http.StatusOK
	if identifier == "" {
		status = http.StatusCreated
	}
	ctx.JSON(status, profile)
}

func (a *API) deleteProfile(ctx *gin.Context) {
	if err := a.manager.DeleteProfile(ctx.Request.Context(), ctx.Param("id")); err != nil {
		if scans.IsNotFound(err) {
			writeError(ctx, http.StatusNotFound, err.Error())
		} else {
			writeError(ctx, http.StatusBadRequest, err.Error())
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}

func (a *API) listScans(ctx *gin.Context) {
	result, err := a.manager.List(ctx.Request.Context())
	if err != nil {
		writeError(ctx, http.StatusInternalServerError, err.Error())
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func (a *API) getScan(ctx *gin.Context) {
	result, err := a.manager.Get(ctx.Request.Context(), ctx.Param("id"))
	if err != nil {
		writeManagerError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func (a *API) deleteScan(ctx *gin.Context) {
	if err := a.manager.Delete(ctx.Request.Context(), ctx.Param("id")); err != nil {
		if errors.Is(err, scans.ErrScanActive) {
			writeError(ctx, http.StatusConflict, err.Error())
			return
		}
		writeManagerError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func (a *API) listHosts(ctx *gin.Context) {
	limit, err := boundedQueryInt(ctx, "limit", 200, 1, 500)
	if err != nil {
		writeError(ctx, http.StatusBadRequest, err.Error())
		return
	}
	offset, err := boundedQueryInt(ctx, "offset", 0, 0, 1_000_000_000)
	if err != nil {
		writeError(ctx, http.StatusBadRequest, err.Error())
		return
	}
	result, err := a.manager.ListHosts(ctx.Request.Context(), ctx.Param("id"), limit, offset)
	if err != nil {
		writeManagerError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func (a *API) getHost(ctx *gin.Context) {
	hostID, err := strconv.ParseInt(ctx.Param("hostID"), 10, 64)
	if err != nil || hostID < 1 {
		writeError(ctx, http.StatusBadRequest, "host ID must be a positive integer")
		return
	}
	result, err := a.manager.GetHost(ctx.Request.Context(), ctx.Param("id"), hostID)
	if err != nil {
		writeManagerError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func (a *API) listEvidence(ctx *gin.Context) {
	limit, err := boundedQueryInt(ctx, "limit", 500, 1, 1000)
	if err != nil {
		writeError(ctx, http.StatusBadRequest, err.Error())
		return
	}
	kind := strings.TrimSpace(ctx.Query("kind"))
	if len(kind) > 128 {
		writeError(ctx, http.StatusBadRequest, "kind is too long")
		return
	}
	result, err := a.manager.ListEvidence(ctx.Request.Context(), ctx.Param("id"), providers.EvidenceQuery{Kind: kind, Limit: limit})
	if err != nil {
		writeManagerError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func (a *API) listTools(ctx *gin.Context) {
	result, err := a.manager.ListTools(ctx.Request.Context(), ctx.Param("id"))
	if err != nil {
		writeManagerError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func (a *API) mapRoutes(ctx *gin.Context) {
	var request struct {
		Target string `json:"target" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&request); err != nil {
		writeError(ctx, http.StatusBadRequest, "route target is required")
		return
	}
	result, err := a.manager.Route(ctx.Request.Context(), ctx.Param("id"), request.Target)
	if err != nil {
		if scans.IsNotFound(err) {
			writeError(ctx, http.StatusNotFound, err.Error())
		} else if strings.Contains(err.Error(), "requires mtr or traceroute") {
			writeError(ctx, http.StatusServiceUnavailable, err.Error())
		} else {
			writeError(ctx, http.StatusBadRequest, err.Error())
		}
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func (a *API) savedRoutes(ctx *gin.Context) {
	result, err := a.manager.SavedRoutes(ctx.Request.Context(), ctx.Param("id"))
	if err != nil {
		writeManagerError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func boundedQueryInt(ctx *gin.Context, name string, fallback, minimum, maximum int) (int, error) {
	raw := ctx.Query(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func (a *API) startScan(ctx *gin.Context) {
	var request struct {
		Target      string `json:"target" binding:"required"`
		ProfileID   string `json:"profileId"`
		OSDetection bool   `json:"osDetection"`
	}
	if err := ctx.ShouldBindJSON(&request); err != nil {
		writeError(ctx, http.StatusBadRequest, "target is required")
		return
	}
	result, err := a.manager.StartRequest(ctx.Request.Context(), scans.ScanRequest{Target: request.Target, ProfileID: request.ProfileID, OSDetection: request.OSDetection})
	if err != nil {
		if errors.Is(err, scans.ErrPrivilegeRequired) {
			writeError(ctx, http.StatusForbidden, err.Error())
			return
		}
		writeError(ctx, http.StatusBadRequest, err.Error())
		return
	}
	ctx.JSON(http.StatusAccepted, result)
}

func (a *API) allScanEvents(ctx *gin.Context) {
	events, unsubscribe := a.manager.SubscribeAll()
	defer unsubscribe()

	ctx.Header("Content-Type", "text/event-stream")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Connection", "keep-alive")
	ctx.Header("X-Accel-Buffering", "no")
	ctx.Status(http.StatusOK)
	flusher, ok := ctx.Writer.(http.Flusher)
	if !ok {
		writeError(ctx, http.StatusInternalServerError, "streaming is not supported")
		return
	}
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case event := <-events:
			if err := writeEvent(ctx.Writer, event); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := fmt.Fprint(ctx.Writer, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-ctx.Request.Context().Done():
			return
		}
	}
}

func (a *API) cancelScan(ctx *gin.Context) {
	if err := a.manager.Cancel(ctx.Param("id")); err != nil {
		writeManagerError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func (a *API) scanEvents(ctx *gin.Context) {
	identifier := ctx.Param("id")
	events, unsubscribe := a.manager.Subscribe(identifier)
	defer unsubscribe()

	scan, err := a.manager.Get(ctx.Request.Context(), identifier)
	if err != nil {
		writeManagerError(ctx, err)
		return
	}

	ctx.Header("Content-Type", "text/event-stream")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Connection", "keep-alive")
	ctx.Header("X-Accel-Buffering", "no")
	ctx.Status(http.StatusOK)
	flusher, ok := ctx.Writer.(http.Flusher)
	if !ok {
		writeError(ctx, http.StatusInternalServerError, "streaming is not supported")
		return
	}
	if err := writeEvent(ctx.Writer, scans.Event{Type: "scan", Scan: &scan}); err != nil {
		return
	}
	tools, err := a.manager.ListTools(ctx.Request.Context(), identifier)
	if err != nil {
		return
	}
	for _, tool := range tools {
		tool := tool
		if err := writeEvent(ctx.Writer, scans.Event{Type: "tool", ScanID: identifier, Tool: &tool}); err != nil {
			return
		}
	}
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case event := <-events:
			if err := writeEvent(ctx.Writer, event); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := fmt.Fprint(ctx.Writer, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-ctx.Request.Context().Done():
			return
		}
	}
}

func writeEvent(writer http.ResponseWriter, event scans.Event) error {
	return sse.Encode(writer, sse.Event{Data: event})
}

func writeManagerError(ctx *gin.Context, err error) {
	if scans.IsNotFound(err) {
		writeError(ctx, http.StatusNotFound, err.Error())
		return
	}
	writeError(ctx, http.StatusInternalServerError, err.Error())
}

func writeError(ctx *gin.Context, status int, message string) {
	ctx.AbortWithStatusJSON(status, gin.H{"error": message})
}
