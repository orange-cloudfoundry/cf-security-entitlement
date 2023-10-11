package main

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

type metricResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

var (
	gHttpTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "cfsecurity",
			Name:      "http_total",
			Help:      "Number of requests",
		},
		[]string{"endpoint", "method", "status"},
	)
)

func init() {
	prometheus.MustRegister(gHttpTotal)
}

func NewMetricResponseWriter(w http.ResponseWriter) *metricResponseWriter {
	return &metricResponseWriter{w, http.StatusOK}
}

func (mrw *metricResponseWriter) WriteHeader(code int) {
	mrw.statusCode = code
	mrw.ResponseWriter.WriteHeader(code)
}

func metricHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		w := NewMetricResponseWriter(res)
		next.ServeHTTP(w, req)
		gHttpTotal.With(prometheus.Labels{
			"endpoint": req.URL.Path,
			"method":   req.Method,
			"status":   fmt.Sprintf("%d", w.statusCode),
		}).Inc()
	})
}
