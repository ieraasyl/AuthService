// Package utils provides pagination utilities for HTTP APIs, supporting both
// offset-based and cursor-based pagination patterns. Offset pagination is ideal
// for small to medium datasets with predictable ordering, while cursor pagination
// is better for large datasets with frequent updates.
package utils

import (
	"fmt"
	"net/http"
	"strconv"
)

const (
	// DefaultPageSize is the default number of items per page when not specified
	DefaultPageSize = 20
	// MaxPageSize is the maximum allowed page size to prevent resource exhaustion
	MaxPageSize = 100
	// MinPageSize is the minimum page size
	MinPageSize = 1
)

// PageParams holds pagination parameters extracted from an HTTP request.
// It includes both the raw page/size values and calculated offset/limit
// for database queries.
type PageParams struct {
	Page     int // 1-based page number
	PageSize int // Number of items per page
	Offset   int // Calculated offset for database query (0-based)
	Limit    int // Calculated limit for database query
}

// PageMeta holds pagination metadata to be included in API responses.
// It helps clients navigate through paginated results and understand
// the total available data.
type PageMeta struct {
	Page         int   `json:"page"`
	PageSize     int   `json:"page_size"`
	TotalPages   int   `json:"total_pages"`
	TotalItems   int64 `json:"total_items"`
	HasPrevious  bool  `json:"has_previous"`
	HasNext      bool  `json:"has_next"`
	PreviousPage *int  `json:"previous_page,omitempty"`
	NextPage     *int  `json:"next_page,omitempty"`
}

// PaginatedResponse wraps data with pagination metadata for API responses.
// This provides a consistent response format across all paginated endpoints.
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Pagination PageMeta    `json:"pagination"`
}

// ParsePageParams extracts and validates pagination parameters from an HTTP request.
// It reads the "page" and "page_size" query parameters, applies defaults and constraints,
// and calculates the offset and limit for database queries.
//
// Query parameters:
//   - page: 1-based page number (default: 1, min: 1)
//   - page_size: items per page (default: 20, min: 1, max: 100)
//
// Example:
//
//	params := utils.ParsePageParams(r)
//	users, err := db.GetUsers(ctx, params.Offset, params.Limit)
//	meta := params.CalculateMeta(totalUsers)
func ParsePageParams(r *http.Request) PageParams {
	page := parseIntParam(r, "page", 1)
	pageSize := parseIntParam(r, "page_size", DefaultPageSize)

	// Validate and constrain parameters
	if page < 1 {
		page = 1
	}
	if pageSize < MinPageSize {
		pageSize = MinPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}

	// Calculate offset and limit
	offset := (page - 1) * pageSize
	limit := pageSize

	return PageParams{
		Page:     page,
		PageSize: pageSize,
		Offset:   offset,
		Limit:    limit,
	}
}

// CalculateMeta calculates pagination metadata based on the total number of items.
// This generates information about available pages, navigation, and data ranges.
//
// Example:
//
//	params := utils.ParsePageParams(r)
//	count, _ := db.CountUsers(ctx)
//	meta := params.CalculateMeta(count)
//	response := utils.NewPaginatedResponse(users, params, count)
func (p PageParams) CalculateMeta(totalItems int64) PageMeta {
	totalPages := int((totalItems + int64(p.PageSize) - 1) / int64(p.PageSize))
	if totalPages < 1 {
		totalPages = 1
	}

	hasPrevious := p.Page > 1
	hasNext := p.Page < totalPages

	var previousPage *int
	var nextPage *int

	if hasPrevious {
		prev := p.Page - 1
		previousPage = &prev
	}

	if hasNext {
		next := p.Page + 1
		nextPage = &next
	}

	return PageMeta{
		Page:         p.Page,
		PageSize:     p.PageSize,
		TotalPages:   totalPages,
		TotalItems:   totalItems,
		HasPrevious:  hasPrevious,
		HasNext:      hasNext,
		PreviousPage: previousPage,
		NextPage:     nextPage,
	}
}

// NewPaginatedResponse creates a paginated response combining data with metadata.
// This is a convenience function that wraps the data and automatically calculates
// pagination metadata.
//
// Example:
//
//	params := utils.ParsePageParams(r)
//	users, _ := db.GetUsers(ctx, params.Offset, params.Limit)
//	totalUsers, _ := db.CountUsers(ctx)
//	response := utils.NewPaginatedResponse(users, params, totalUsers)
//	utils.RespondWithJSON(w, r, http.StatusOK, response)
func NewPaginatedResponse(data interface{}, params PageParams, totalItems int64) PaginatedResponse {
	return PaginatedResponse{
		Data:       data,
		Pagination: params.CalculateMeta(totalItems),
	}
}

// IsValidPage checks if the current page number is within the valid range.
// Returns false if the page exceeds the total number of pages.
func (p PageParams) IsValidPage(totalItems int64) bool {
	meta := p.CalculateMeta(totalItems)
	return p.Page <= meta.TotalPages
}

// GetRange returns the 1-based item range for the current page.
// Useful for displaying "Showing items 21-40 of 100" to users.
//
// Example:
//
//	start, end := params.GetRange(totalItems)
//	fmt.Printf("Showing items %d-%d of %d", start, end, totalItems)
func (p PageParams) GetRange(totalItems int64) (start, end int64) {
	start = int64(p.Offset) + 1
	end = start + int64(p.PageSize) - 1

	if end > totalItems {
		end = totalItems
	}

	if start > totalItems {
		start = totalItems
	}

	return start, end
}

// String returns a human-readable representation of pagination metadata.
func (m PageMeta) String() string {
	return fmt.Sprintf("Page %d/%d (%d items per page, %d total items)",
		m.Page, m.TotalPages, m.PageSize, m.TotalItems)
}

// parseIntParam safely parses an integer query parameter with a default fallback.
func parseIntParam(r *http.Request, key string, defaultValue int) int {
	valueStr := r.URL.Query().Get(key)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

// Cursor-based pagination for large datasets and real-time data

// CursorParams holds cursor-based pagination parameters.
// Cursor pagination is more efficient for large datasets and handles
// concurrent updates better than offset pagination.
type CursorParams struct {
	Cursor    string // Opaque cursor string
	Limit     int    // Number of items to return
	Direction string // "next" or "prev"
}

// CursorMeta holds cursor-based pagination metadata for responses.
type CursorMeta struct {
	NextCursor     *string `json:"next_cursor,omitempty"`
	PreviousCursor *string `json:"previous_cursor,omitempty"`
	HasMore        bool    `json:"has_more"`
	Limit          int     `json:"limit"`
}

// CursorResponse wraps data with cursor-based pagination metadata.
type CursorResponse struct {
	Data   interface{} `json:"data"`
	Cursor CursorMeta  `json:"cursor"`
}

// ParseCursorParams extracts cursor-based pagination parameters from request.
// Query parameters:
//   - cursor: opaque cursor string from previous response
//   - limit: number of items to return (default: 20, min: 1, max: 100)
//   - direction: "next" or "prev" (default: "next")
//
// Example:
//
//	params := utils.ParseCursorParams(r)
//	items, nextCursor, err := db.GetItemsAfterCursor(ctx, params.Cursor, params.Limit)
func ParseCursorParams(r *http.Request) CursorParams {
	cursor := r.URL.Query().Get("cursor")
	limit := parseIntParam(r, "limit", DefaultPageSize)
	direction := r.URL.Query().Get("direction")

	if limit < MinPageSize {
		limit = MinPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}

	if direction != "prev" && direction != "next" {
		direction = "next"
	}

	return CursorParams{
		Cursor:    cursor,
		Limit:     limit,
		Direction: direction,
	}
}

// NewCursorResponse creates a cursor-based paginated response.
// The cursors are opaque strings that encode position information.
// hasMore indicates if more results are available in the requested direction.
//
// Example:
//
//	response := utils.NewCursorResponse(items, &nextCursor, nil, true, 20)
//	utils.RespondWithJSON(w, r, http.StatusOK, response)
func NewCursorResponse(data interface{}, nextCursor *string, previousCursor *string, hasMore bool, limit int) CursorResponse {
	return CursorResponse{
		Data: data,
		Cursor: CursorMeta{
			NextCursor:     nextCursor,
			PreviousCursor: previousCursor,
			HasMore:        hasMore,
			Limit:          limit,
		},
	}
}
