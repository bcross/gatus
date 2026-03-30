package api

import (
	"fmt"

	"github.com/TwiN/gatus/v5/config"
	"github.com/TwiN/gatus/v5/config/suite"
	"github.com/TwiN/gatus/v5/storage/store"
	"github.com/TwiN/gatus/v5/storage/store/common/paging"
	"github.com/gofiber/fiber/v2"
)

// SuiteStatuses handles requests to retrieve all suite statuses
func SuiteStatuses(cfg *config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		page, pageSize := extractPageAndPageSizeFromRequest(c, 100)
		params := paging.NewSuiteStatusParams().WithPagination(page, pageSize)
		suiteStatuses, err := store.Get().GetAllSuiteStatuses(params)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("Failed to retrieve suite statuses: %v", err),
			})
		}
		// If no statuses exist yet, create empty ones from config
		if len(suiteStatuses) == 0 {
			for _, s := range cfg.Suites {
				if s.IsEnabled() {
					suiteStatuses = append(suiteStatuses, suite.NewStatus(s))
				}
			}
		}
		return c.Status(fiber.StatusOK).JSON(suiteStatuses)
	}
}

// SuiteStatus handles requests to retrieve a single suite's status
func SuiteStatus(cfg *config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		page, pageSize := extractPageAndPageSizeFromRequest(c, 100)
		key := c.Params("key")
		params := paging.NewSuiteStatusParams().WithPagination(page, pageSize)
		status, err := store.Get().GetSuiteStatusByKey(key, params)
		if err != nil || status == nil {
			// Try to find the suite in config
			for _, s := range cfg.Suites {
				if s.Key() == key {
					status = suite.NewStatus(s)
					break
				}
			}
			if status == nil {
				return c.Status(404).JSON(fiber.Map{
					"error": fmt.Sprintf("Suite with key '%s' not found", key),
				})
			}
		}
		return c.Status(fiber.StatusOK).JSON(status)
	}
}

// VisibilityAwareSuiteStatuses handles requests to retrieve all suite statuses
// with visibility filtering based on authentication status.
func VisibilityAwareSuiteStatuses(cfg *config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		page, pageSize := extractPageAndPageSizeFromRequest(c, 100)
		isAuthenticated := IsAuthenticated(c, cfg)

		// If not authenticated, only public suites are returned
		if !isAuthenticated {
			return handleUnauthenticatedSuiteStatuses(c, cfg, page, pageSize)
		}

		// Authenticated users get all suites
		return SuiteStatuses(cfg)(c)
	}
}

// handleUnauthenticatedSuiteStatuses returns only public suites for unauthenticated users
func handleUnauthenticatedSuiteStatuses(c *fiber.Ctx, cfg *config.Config, page, pageSize int) error {
	params := paging.NewSuiteStatusParams().WithPagination(page, pageSize)
	allStatuses, err := store.Get().GetAllSuiteStatuses(params)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to retrieve suite statuses: %v", err),
		})
	}

	// If no statuses exist yet, create empty ones from config but only for public suites
	if len(allStatuses) == 0 {
		for _, s := range cfg.Suites {
			if s.IsEnabled() && s.IsPublic() {
				allStatuses = append(allStatuses, suite.NewStatus(s))
			}
		}
	}

	// Filter to only public suites
	var filteredStatuses []*suite.Status
	for _, status := range allStatuses {
		if IsSuitePublic(cfg, NormalizeKey(status.Key)) {
			filteredStatuses = append(filteredStatuses, status)
		}
	}

	return c.Status(fiber.StatusOK).JSON(filteredStatuses)
}

// VisibilityAwareSuiteStatus retrieves a single suite's status with visibility checking.
func VisibilityAwareSuiteStatus(cfg *config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := c.Params("key")

		isAuthenticated := IsAuthenticated(c, cfg)
		isPublic := IsSuitePublic(cfg, NormalizeKey(key))

		// If suite is private and user is not authenticated, return 401
		if !isPublic && !isAuthenticated {
			return c.Status(401).JSON(fiber.Map{
				"error": "Unauthorized",
			})
		}

		// Let the standard handler process the request
		return SuiteStatus(cfg)(c)
	}
}
