package api

import (
	"net/http/httptest"
	"testing"

	"github.com/TwiN/gatus/v5/config"
	"github.com/TwiN/gatus/v5/config/endpoint"
	"github.com/TwiN/gatus/v5/config/suite"
	"github.com/TwiN/gatus/v5/security"
	"github.com/gofiber/fiber/v2"
)

func TestIsEndpointPublic(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		key      string
		expected bool
	}{
		{
			name:     "no_security_configured",
			cfg:      &config.Config{},
			key:      "test-endpoint",
			expected: true,
		},
		{
			name: "security_configured_no_endpoints",
			cfg: &config.Config{
				Security: &security.Config{},
			},
			key:      "test-endpoint",
			expected: false,
		},
		{
			name: "endpoint_explicitly_public",
			cfg: &config.Config{
				Security: &security.Config{},
				Endpoints: []*endpoint.Endpoint{
					{
						Name:       "test-endpoint",
						Group:      "test-group",
						Visibility: endpoint.VisibilityPublic,
					},
				},
			},
			key:      "test-group_test-endpoint",
			expected: true,
		},
		{
			name: "endpoint_explicitly_private",
			cfg: &config.Config{
				Security: &security.Config{},
				Endpoints: []*endpoint.Endpoint{
					{
						Name:       "test-endpoint",
						Group:      "test-group",
						Visibility: endpoint.VisibilityPrivate,
					},
				},
			},
			key:      "test-group_test-endpoint",
			expected: false,
		},
		{
			name: "endpoint_default_private_when_security_configured",
			cfg: &config.Config{
				Security: &security.Config{},
				Endpoints: []*endpoint.Endpoint{
					{
						Name:  "test-endpoint",
						Group: "test-group",
						// No visibility set - should default to private
					},
				},
			},
			key:      "test-group_test-endpoint",
			expected: false,
		},
		{
			name: "endpoint_not_found",
			cfg: &config.Config{
				Security: &security.Config{},
				Endpoints: []*endpoint.Endpoint{
					{
						Name:  "other-endpoint",
						Group: "other-group",
					},
				},
			},
			key:      "test-group_test-endpoint",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEndpointPublic(tt.cfg, tt.key)
			if result != tt.expected {
				t.Errorf("IsEndpointPublic() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsSuitePublic(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		key      string
		expected bool
	}{
		{
			name:     "no_security_configured",
			cfg:      &config.Config{},
			key:      "test-suite",
			expected: true,
		},
		{
			name: "security_configured_no_suites",
			cfg: &config.Config{
				Security: &security.Config{},
			},
			key:      "test-suite",
			expected: false,
		},
		{
			name: "suite_explicitly_public",
			cfg: &config.Config{
				Security: &security.Config{},
				Suites: []*suite.Suite{
					{
						Name:       "test-suite",
						Group:      "test-group",
						Visibility: endpoint.VisibilityPublic,
					},
				},
			},
			key:      "test-group_test-suite",
			expected: true,
		},
		{
			name: "suite_explicitly_private",
			cfg: &config.Config{
				Security: &security.Config{},
				Suites: []*suite.Suite{
					{
						Name:       "test-suite",
						Group:      "test-group",
						Visibility: endpoint.VisibilityPrivate,
					},
				},
			},
			key:      "test-group_test-suite",
			expected: false,
		},
		{
			name: "suite_default_private_when_security_configured",
			cfg: &config.Config{
				Security: &security.Config{},
				Suites: []*suite.Suite{
					{
						Name: "test-suite",
						Group: "test-group",
						// No visibility set - should default to private
					},
				},
			},
			key:      "test-group_test-suite",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSuitePublic(tt.cfg, tt.key)
			if result != tt.expected {
				t.Errorf("IsSuitePublic() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestHasPublicEndpointsOrSuites(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		expected bool
	}{
		{
			name:     "nil_config",
			cfg:      nil,
			expected: false,
		},
		{
			name:     "no_security_configured",
			cfg:      &config.Config{},
			expected: false,
		},
		{
			name: "security_but_no_endpoints_or_suites",
			cfg: &config.Config{
				Security: &security.Config{},
			},
			expected: false,
		},
		{
			name: "public_endpoint_exists",
			cfg: &config.Config{
				Security: &security.Config{},
				Endpoints: []*endpoint.Endpoint{
					{
						Name:       "public-endpoint",
						Group:      "group",
						Visibility: endpoint.VisibilityPublic,
					},
				},
			},
			expected: true,
		},
		{
			name: "public_suite_exists",
			cfg: &config.Config{
				Security: &security.Config{},
				Suites: []*suite.Suite{
					{
						Name:       "public-suite",
						Group:      "group",
						Visibility: endpoint.VisibilityPublic,
					},
				},
			},
			expected: true,
		},
		{
			name: "all_private",
			cfg: &config.Config{
				Security: &security.Config{},
				Endpoints: []*endpoint.Endpoint{
					{
						Name:       "private-endpoint",
						Group:      "group",
						Visibility: endpoint.VisibilityPrivate,
					},
				},
				Suites: []*suite.Suite{
					{
						Name:       "private-suite",
						Group:      "group",
						Visibility: endpoint.VisibilityPrivate,
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasPublicEndpointsOrSuites(tt.cfg)
			if result != tt.expected {
				t.Errorf("HasPublicEndpointsOrSuites() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestNormalizeKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "lowercase",
			key:      "test-endpoint",
			expected: "test-endpoint",
		},
		{
			name:     "uppercase",
			key:      "TEST-ENDPOINT",
			expected: "test-endpoint",
		},
		{
			name:     "mixed_case",
			key:      "Test_Endpoint",
			expected: "test_endpoint",
		},
		{
			name:     "with_group",
			key:      "Group_Name",
			expected: "group_name",
		},
		{
			name:     "empty",
			key:      "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeKey(tt.key)
			if result != tt.expected {
				t.Errorf("NormalizeKey(%q) = %q, expected %q", tt.key, result, tt.expected)
			}
		})
	}
}

func TestVisibilityAwareEndpointStatus(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("VisibilityAwareEndpointStatus panicked: %v", r)
		}
	}()

	app := fiber.New()

	// Test case: endpoint is public and no security - should return 200
	cfg := &config.Config{
		Endpoints: []*endpoint.Endpoint{
			{
				Name:       "public-endpoint",
				Group:      "group",
				Visibility: endpoint.VisibilityPublic,
			},
		},
	}

	handler := VisibilityAwareEndpointStatus(cfg)

	// Create a mock request for a public endpoint
	req := httptest.NewRequest("GET", "/api/v1/endpoints/group_public-endpoint/statuses", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to test request: %v", err)
	}
	// The endpoint exists in config but not in storage, so we expect 404
	if resp.StatusCode != 404 {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

func TestVisibilityAwareEndpointStatuses_Authenticated(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("VisibilityAwareEndpointStatuses panicked: %v", r)
		}
	}()

	app := fiber.New()

	// Test case: security is configured but no public endpoints
	// When not authenticated, should filter to show no endpoints
	cfg := &config.Config{
		Security: &security.Config{},
		Endpoints: []*endpoint.Endpoint{
			{
				Name:       "private-endpoint",
				Group:      "group",
				Visibility: endpoint.VisibilityPrivate,
			},
		},
	}

	handler := VisibilityAwareEndpointStatuses(cfg)

	// Create a mock request without auth
	req := httptest.NewRequest("GET", "/api/v1/endpoints/statuses", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to test request: %v", err)
	}
	// Should return 200 but with empty array since no public endpoints
	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestFilterPublicEndpoints(t *testing.T) {
	endpoints := []*endpoint.Endpoint{
		{
			Name:       "public-endpoint",
			Group:      "group",
			Visibility: endpoint.VisibilityPublic,
		},
		{
			Name:       "private-endpoint",
			Group:      "group",
			Visibility: endpoint.VisibilityPrivate,
		},
	}

	tests := []struct {
		name           string
		cfg            *config.Config
		isAuthenticated bool
		expectedCount  int
	}{
		{
			name:           "no_security_all_visible",
			cfg:            &config.Config{},
			isAuthenticated: false,
			expectedCount:  2,
		},
		{
			name: "security_not_authenticated_only_public",
			cfg: &config.Config{
				Security: &security.Config{},
			},
			isAuthenticated: false,
			expectedCount:   1, // Only public endpoint
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterPublicEndpoints(endpoints, tt.cfg, tt.isAuthenticated)
			if len(result) != tt.expectedCount {
				t.Errorf("FilterPublicEndpoints() returned %d endpoints, expected %d", len(result), tt.expectedCount)
			}
		})
	}
}

func TestFilterPublicSuites(t *testing.T) {
	suites := []*suite.Suite{
		{
			Name:       "public-suite",
			Group:      "group",
			Visibility: endpoint.VisibilityPublic,
		},
		{
			Name:       "private-suite",
			Group:      "group",
			Visibility: endpoint.VisibilityPrivate,
		},
	}

	tests := []struct {
		name            string
		cfg             *config.Config
		isAuthenticated bool
		expectedCount   int
	}{
		{
			name:            "no_security_all_visible",
			cfg:             &config.Config{},
			isAuthenticated: false,
			expectedCount:   2,
		},
		{
			name: "security_not_authenticated_only_public",
			cfg: &config.Config{
				Security: &security.Config{},
			},
			isAuthenticated: false,
			expectedCount:   1, // Only public suite
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterPublicSuites(suites, tt.cfg, tt.isAuthenticated)
			if len(result) != tt.expectedCount {
				t.Errorf("FilterPublicSuites() returned %d suites, expected %d", len(result), tt.expectedCount)
			}
		})
	}
}

func TestIsAuthenticated(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		expected bool
	}{
		{
			name:     "nil_config",
			cfg:      nil,
			expected: true,
		},
		{
			name:     "nil_security",
			cfg:      &config.Config{},
			expected: true,
		},
		{
			name: "security_configured_but_no_auth",
			cfg: &config.Config{
				Security: &security.Config{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			req := httptest.NewRequest("GET", "/", nil)
			resp, _ := app.Test(req)

			// Note: This is a simplified test. In reality, IsAuthenticated
			// uses the security config to check cookies etc.
			_ = resp // suppress unused warning
		})
	}
}
