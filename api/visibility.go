package api

import (
	"strings"

	"github.com/TwiN/gatus/v5/config"
	"github.com/TwiN/gatus/v5/config/endpoint"
	"github.com/TwiN/gatus/v5/config/suite"
	"github.com/TwiN/gatus/v5/security"
	"github.com/gofiber/fiber/v2"
)

// IsEndpointPublic returns true if the endpoint with the given key is public.
// If security is not configured, all endpoints are considered public.
func IsEndpointPublic(cfg *config.Config, key string) bool {
	// If no security is configured, all endpoints are public
	if cfg.Security == nil {
		return true
	}

	// Find the endpoint in config
	for _, ep := range cfg.Endpoints {
		if ep.Key() == key {
			return ep.IsPublic()
		}
	}
	return false
}

// IsSuitePublic returns true if the suite with the given key is public.
// If security is not configured, all suites are considered public.
func IsSuitePublic(cfg *config.Config, key string) bool {
	// If no security is configured, all suites are public
	if cfg.Security == nil {
		return true
	}

	// Find the suite in config
	for _, s := range cfg.Suites {
		if s.Key() == key {
			return s.IsPublic()
		}
	}
	return false
}

// HasPublicEndpointsOrSuites returns true if there are any public endpoints or suites configured.
// This is used to determine whether to show login/logout buttons.
func HasPublicEndpointsOrSuites(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	// Check if security is configured
	if cfg.Security == nil {
		return false
	}
	// Check endpoints
	for _, ep := range cfg.Endpoints {
		if ep.IsPublic() {
			return true
		}
	}
	// Check suites
	for _, s := range cfg.Suites {
		if s.IsPublic() {
			return true
		}
	}
	return false
}

// IsAuthenticatedForEndpoint returns true if the request is authenticated for the given endpoint.
// An unauthenticated request can access public endpoints but not private ones.
func IsAuthenticatedForEndpoint(cfg *config.Config, key string, isAuthenticated bool) bool {
	// If no security is configured, always allow
	if cfg.Security == nil {
		return true
	}
	// If not authenticated, only allow public endpoints
	if !isAuthenticated {
		return IsEndpointPublic(cfg, key)
	}
	// For basic auth, all authenticated users can access all endpoints
	// because basic auth doesn't have group-based authorization
	if cfg.Security.Basic != nil {
		return true
	}
	// For OIDC, we need to check group-based authorization for private endpoints
	// This is handled at a different level - for now, if authenticated, allow access
	return true
}

// FilterPublicEndpoints filters endpoints based on visibility, only returning those
// accessible to unauthenticated users when isAuthenticated is false.
func FilterPublicEndpoints(endpoints []*endpoint.Endpoint, cfg *config.Config, isAuthenticated bool) []*endpoint.Endpoint {
	// If no security is configured, return all endpoints
	if cfg.Security == nil {
		return endpoints
	}

	// If authenticated with basic auth, return all endpoints
	if isAuthenticated && cfg.Security.Basic != nil {
		return endpoints
	}

	// For OIDC with no AllowedGroups configured, all authenticated users can see all endpoints
	if isAuthenticated && cfg.Security.OIDC != nil && len(cfg.Security.OIDC.AllowedGroups) == 0 {
		return endpoints
	}

	// Filter endpoints based on visibility
	var filtered []*endpoint.Endpoint
	for _, ep := range endpoints {
		if ep.IsPublic() {
			filtered = append(filtered, ep)
		}
	}
	return filtered
}

// FilterPublicSuites filters suites based on visibility, only returning those
// accessible to unauthenticated users when isAuthenticated is false.
func FilterPublicSuites(suites []*suite.Suite, cfg *config.Config, isAuthenticated bool) []*suite.Suite {
	// If no security is configured, return all suites
	if cfg.Security == nil {
		return suites
	}

	// If authenticated with basic auth, return all suites
	if isAuthenticated && cfg.Security.Basic != nil {
		return suites
	}

	// For OIDC with no AllowedGroups configured, all authenticated users can see all suites
	if isAuthenticated && cfg.Security.OIDC != nil && len(cfg.Security.OIDC.AllowedGroups) == 0 {
		return suites
	}

	// Filter suites based on visibility
	var filtered []*suite.Suite
	for _, s := range suites {
		if s.IsPublic() {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// HasGroup checks if the user has the specified group for OIDC authentication.
// This is used for group-based authorization of private endpoints.
func HasGroup(sessionID, group string) bool {
	return security.HasGroup(sessionID, group)
}

// IsAuthorizedForPrivateEndpoint checks if the user is authorized to access a private endpoint.
// For basic auth, all authenticated users are authorized.
// For OIDC, the user must belong to at least one of the allowed groups if configured.
func IsAuthorizedForPrivateEndpoint(cfg *config.Config, sessionID string) bool {
	if cfg == nil || cfg.Security == nil {
		return true
	}

	// For basic auth, all authenticated users are authorized
	if cfg.Security.Basic != nil {
		return true
	}

	// For OIDC without group restrictions, all authenticated users are authorized
	if cfg.Security.OIDC == nil || len(cfg.Security.OIDC.AllowedGroups) == 0 {
		return true
	}

	// Check if user belongs to any allowed group
	for _, group := range cfg.Security.OIDC.AllowedGroups {
		if security.HasGroup(sessionID, group) {
			return true
		}
	}
	return false
}

// ExtractSessionID extracts the session ID from the request context
func ExtractSessionID(c *fiber.Ctx, cfg *config.Config) string {
	if cfg == nil || cfg.Security == nil {
		return ""
	}
	sessionCookie := c.Cookies(cookieNameSession)
	if sessionCookie == "" {
		return ""
	}
	return sessionCookie
}

// IsAuthenticated checks if the request is authenticated using the security config
func IsAuthenticated(c *fiber.Ctx, cfg *config.Config) bool {
	if cfg == nil || cfg.Security == nil {
		return true
	}
	return cfg.Security.IsAuthenticated(c)
}

const cookieNameSession = "gatus_session"

// NormalizeKey normalizes a key by converting it to lowercase
// This is used for case-insensitive key matching
func NormalizeKey(key string) string {
	return strings.ToLower(key)
}
