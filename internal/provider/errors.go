// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"errors"

	"github.com/Encryption-Consulting-LLC/terraform-provider-certsecure/internal/client"
)

// describeAPIError maps a CertSecure client error to a diagnostic summary and
// detail, following the provider's HTTP error mapping.
func describeAPIError(err error) (summary, detail string) {
	var apiErr *client.APIError
	switch {
	case client.IsUnauthorized(err):
		return "CertSecure token missing, invalid, or expired.", err.Error()
	case client.IsForbidden(err):
		return "Token lacks permission for this CA/template.", err.Error()
	case client.IsBadRequest(err) && errors.As(err, &apiErr):
		msg := apiErr.Message
		if msg == "" {
			msg = apiErr.Body
		}
		return "CertSecure rejected the request: " + msg, err.Error()
	case client.IsNotFound(err):
		return "Not found in CertSecure.", err.Error()
	case client.IsServerError(err):
		return "CertSecure server error.", err.Error()
	default:
		return "CertSecure request failed.", err.Error()
	}
}
