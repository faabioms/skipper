package auth

import (
	"net/http"

	"github.com/zalando/skipper/filters"
)

const WebhookName = "webhook"

type (
	webhookSpec   struct{}
	webhookFilter struct {
		authClient *authClient
	}
)

// NewWebhook creates a new auth filter specification
// to validate authorization for requests.
func NewWebhook() filters.Spec {
	return &webhookSpec{}
}

func (s *webhookSpec) Name() string {
	return WebhookName
}

// CreateFilter creates an auth filter. The first argument is an URL
// string.
//
//     s.CreateFilter("https://my-auth-service.example.org/auth")
//
func (s *webhookSpec) CreateFilter(args []interface{}) (filters.Filter, error) {
	if l := len(args); l == 0 || l > 2 {
		return nil, filters.ErrInvalidFilterParameters
	}

	s, ok := args[0].(string)
	if !ok {
		return nil, filters.ErrInvalidFilterParameters
	}

	ac, err := newAuthClient(s)
	if err != nil {
		return nil, filters.ErrInvalidFilterParameters
	}

	return &webhookFilter{
		authClient: ac,
	}
}

func copyHeader(to, from http.Header) {
	for k, v := range from {
		to[http.CanonicalHeaderKey(k)] = v
	}
}

func (f *webhookFilter) Request(ctx filters.FilterContext) {
	statusCode, err := f.ac.getWebhook(ctx.Request())
	if err != nil {
		unauthorized(ctx, WebhookName, authServiceAccess, f.authClient.url.Hostname())
	}
	if statusCode >= 400 {
		unauthorized(ctx, WebhookName, invalidAccess, f.authClient.url.Hostname())
	}
	authorized(ctx, WebhookName)
}

func (f *webhookFilter) Response(filters.FilterContext) {}
