// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net/url"
	"strings"
)

// Task status values (Task.StatusInfo) written by CertSecure.
const (
	TaskInitialized = "INITIALIZED"
	TaskProcessing  = "PROCESSING"
	TaskPending     = "PENDING"
	TaskOK          = "OK"
	TaskError       = "ERROR"
)

// Task is the response of GET /tasks?taskID=<id>.
type Task struct {
	TaskID     string `json:"TaskID"`
	TaskName   string `json:"taskName"`
	Status     string `json:"status"`
	StatusInfo string `json:"statusInfo"`
	Details    string `json:"details"`
	CreatedOn  string `json:"createdOn"`
	UpdatedOn  string `json:"updatedOn"`
}

// IsPendingApproval reports whether the task waits for CA manager approval
// (status "Pending Approval by Admin", statusInfo PENDING).
func (t *Task) IsPendingApproval() bool {
	return strings.EqualFold(t.StatusInfo, TaskPending) ||
		strings.Contains(strings.ToLower(t.Status), "pending approval")
}

// IsFailed reports whether the task ended in an error (denied by policy, CA
// error, ...).
func (t *Task) IsFailed() bool { return strings.EqualFold(t.StatusInfo, TaskError) }

// IsDone reports whether the task completed successfully.
func (t *Task) IsDone() bool { return strings.EqualFold(t.StatusInfo, TaskOK) }

// GetTask calls GET /tasks?taskID=<id>. It returns an *APIError with status
// 404 for unknown task IDs.
//
// The path has no trailing slash: "/tasks/" answers 404.
func (c *Client) GetTask(ctx context.Context, taskID string) (*Task, error) {
	resp, err := c.get(ctx, "/tasks", url.Values{"taskID": {taskID}}, true)
	if err != nil {
		return nil, err
	}
	var t Task
	if err := decodeJSON(resp, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
