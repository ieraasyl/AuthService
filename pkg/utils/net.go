// Package utils provides common utility functions for HTTP operations,
// including IP address extraction and validation. These utilities handle
// various proxy configurations and IP address formats.
package utils

import (
	"net/http"
	"strings"
)

// ExtractClientIP extracts the real client IP address from HTTP request headers.
// It checks headers in the following priority order:
// 1. X-Forwarded-For (takes the first IP if multiple are present)
// 2. X-Real-IP
// 3. RemoteAddr (strips port if present)
//
// This function is useful when the application is behind a reverse proxy or load balancer.
func ExtractClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first (reverse proxy/load balancer)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Trim spaces first
		xff = strings.TrimSpace(xff)

		// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
		// Take the first IP (the original client)
		if idx := strings.IndexAny(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return xff
	}

	// Try X-Real-IP header (alternative proxy header)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	// RemoteAddr format: "IP:port" or "[IPv6]:port"
	remoteAddr := r.RemoteAddr

	// Handle IPv6 addresses with port: [::1]:8080
	if strings.HasPrefix(remoteAddr, "[") {
		if idx := strings.LastIndex(remoteAddr, "]"); idx != -1 {
			return remoteAddr[1:idx]
		}
	}

	// Handle IPv4 addresses with port: 127.0.0.1:8080
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		return remoteAddr[:idx]
	}

	return remoteAddr
}

// IsPrivateIP checks if an IP address is private, local, or link-local.
// Returns true for:
//   - Loopback addresses (127.0.0.0/8, ::1)
//   - Private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//   - Link-local addresses (169.254.0.0/16, fe80::/10)
//   - IPv6 unique local addresses (fc00::/7)
//
// This is useful for skipping geolocation lookups or applying different
// security rules for internal traffic.
//
// Example:
//
//	if utils.IsPrivateIP(clientIP) {
//	    // Skip geolocation for local IPs
//	    location = "Local Network"
//	}
func IsPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "172.17.") ||
		strings.HasPrefix(ip, "172.18.") ||
		strings.HasPrefix(ip, "172.19.") ||
		strings.HasPrefix(ip, "172.20.") ||
		strings.HasPrefix(ip, "172.21.") ||
		strings.HasPrefix(ip, "172.22.") ||
		strings.HasPrefix(ip, "172.23.") ||
		strings.HasPrefix(ip, "172.24.") ||
		strings.HasPrefix(ip, "172.25.") ||
		strings.HasPrefix(ip, "172.26.") ||
		strings.HasPrefix(ip, "172.27.") ||
		strings.HasPrefix(ip, "172.28.") ||
		strings.HasPrefix(ip, "172.29.") ||
		strings.HasPrefix(ip, "172.30.") ||
		strings.HasPrefix(ip, "172.31.") ||
		strings.HasPrefix(ip, "169.254.") || // Link-local
		ip == "::1" || // IPv6 loopback
		strings.HasPrefix(ip, "fe80:") || // IPv6 link-local
		strings.HasPrefix(ip, "fc00:") || // IPv6 unique local
		strings.HasPrefix(ip, "fd00:") // IPv6 unique local
}
