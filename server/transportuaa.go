package main

import (
	"net/http"
	"net/url"
)

// Cf client call /v3/info to retrieve uaa url but this url need to be set to domain given by user
// this transport change request domain to set correct domain
type TranslateTransport struct {
	transport     http.RoundTripper
	oldUrl        *url.URL
	translatedUrl *url.URL
}

func urlMustParse(urlRaw string) *url.URL {
	u, err := url.Parse(urlRaw)
	if err != nil {
		panic(err)
	}
	return u
}

func NewTranslateTransport(transport http.RoundTripper, oldUrl, translatedUrl string) *TranslateTransport {
	return &TranslateTransport{
		transport:     transport,
		translatedUrl: urlMustParse(translatedUrl),
		oldUrl:        urlMustParse(oldUrl),
	}
}

func (t TranslateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == t.oldUrl.Host {
		finalUrl := urlMustParse(t.translatedUrl.String())
		finalUrl.Path = req.URL.Path
		req.URL = finalUrl
	}
	return t.transport.RoundTrip(req)
}
