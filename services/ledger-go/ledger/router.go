package ledger

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// Middleware defines a function that wraps an http.HandlerFunc.
type Middleware func(http.HandlerFunc) http.HandlerFunc

type routeEntry struct {
	method  string
	path    string
	handler http.HandlerFunc
}

// Router implements a lightweight, high-performance HTTP multiplexer.
type Router struct {
	routes      []routeEntry
	middlewares []Middleware
	mutex       sync.RWMutex
	requestLogs []string
	maxLogs     int
}

// NewRouter initializes an empty Router.
func NewRouter() *Router {
	r := &Router{
		routes:      make([]routeEntry, 0),
		middlewares: make([]Middleware, 0),
		requestLogs: make([]string, 0),
		maxLogs:     1000,
	}

	// Register default logging & recovery middlewares
	r.Use(r.recoveryMiddleware)
	r.Use(r.loggingMiddleware)

	return r
}

// Use appends a middleware to the execution chain.
func (r *Router) Use(mw Middleware) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.middlewares = append(r.middlewares, mw)
}

// HandleFunc registers a new route handler for a given HTTP method and path.
func (r *Router) HandleFunc(method, path string, handler http.HandlerFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.routes = append(r.routes, routeEntry{
		method:  strings.ToUpper(method),
		path:    path,
		handler: handler,
	})
}

// ServeHTTP implements the http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mutex.RLock()
	var matchedHandler http.HandlerFunc

	for _, entry := range r.routes {
		if entry.method == req.Method && r.matchPath(entry.path, req.URL.Path) {
			matchedHandler = entry.handler
			break
		}
	}
	r.mutex.RUnlock()

	if matchedHandler == nil {
		http.NotFound(w, req)
		return
	}

	// Apply middlewares in reverse order
	finalHandler := matchedHandler
	r.mutex.RLock()
	for i := len(r.middlewares) - 1; i >= 0; i-- {
		finalHandler = r.middlewares[i](finalHandler)
	}
	r.mutex.RUnlock()

	finalHandler(w, req)
}

func (r *Router) matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix)
	}
	return false
}

func (r *Router) loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		next(w, req)
		duration := time.Since(start)

		r.mutex.Lock()
		logEntry := strings.Join([]string{
			time.Now().Format(time.RFC3339),
			req.Method,
			req.URL.Path,
			duration.String(),
		}, " ")
		r.requestLogs = append(r.requestLogs, logEntry)
		if len(r.requestLogs) > r.maxLogs {
			r.requestLogs = r.requestLogs[1:]
		}
		r.mutex.Unlock()
	}
}

func (r *Router) recoveryMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next(w, req)
	}
}

// GetRecentLogs returns a copy of captured access logs.
func (r *Router) GetRecentLogs() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	res := make([]string, len(r.requestLogs))
	copy(res, r.requestLogs)
	return res
}

// RouteCount returns the number of registered endpoints.
func (r *Router) RouteCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return len(r.routes)
}
