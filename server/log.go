package main

import (
	"net/http"
	"strings"

	"github.com/gorilla/context"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	log "github.com/sirupsen/logrus"
)

func loadLogConfig(c model.ConfigServer) {
	if c.LogJSON != nil {
		if *c.LogJSON {
			log.SetFormatter(&log.JSONFormatter{})
		} else {
			log.SetFormatter(&log.TextFormatter{
				DisableColors: c.LogNoColor,
			})
		}
	}

	if c.LogLevel == "" {
		return
	}
	switch strings.ToUpper(c.LogLevel) {
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
		return
	case "WARN":
		log.SetLevel(log.WarnLevel)
		return
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
		return
	case "PANIC":
		log.SetLevel(log.PanicLevel)
		return
	case "FATAL":
		log.SetLevel(log.FatalLevel)
		return
	}
}

func logHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		fields := log.Fields{
			"method":     req.Method,
			"path":       req.RequestURI,
			"remote":     req.RemoteAddr,
			"host":       req.Host,
			"user-agent": req.UserAgent(),
		}

		xff := req.Header.Get("X-Forwarded-For")
		if xff != "" {
			fields["xff"] = xff
		}

		isAdmin := context.Get(req, ContextIsAdmin)
		if isAdmin != nil {
			fields["is_admin"] = isAdmin.(bool)
		}

		log.WithFields(fields).Infof("handling request")
		next.ServeHTTP(res, req)
	})
}
