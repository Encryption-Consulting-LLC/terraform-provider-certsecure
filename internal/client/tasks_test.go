// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/http"
	"testing"
)

func TestGetTask_Fixtures(t *testing.T) {
	cases := []struct {
		fixture               string
		pending, failed, done bool
	}{
		{"task_processing.json", false, false, false},
		{"task_ok.json", false, false, true},
		{"task_pending_approval.json", true, false, false},
		{"task_error.json", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/tasks" || r.URL.Query().Get("taskID") == "" {
					t.Errorf("unexpected request %s", r.URL)
				}
				writeJSON(w, 200, fixture(t, tc.fixture))
			})
			task, err := c.GetTask(ctx(), "1")
			if err != nil {
				t.Fatal(err)
			}
			if task.IsPendingApproval() != tc.pending || task.IsFailed() != tc.failed || task.IsDone() != tc.done {
				t.Errorf("task %+v: pending=%v failed=%v done=%v", task, task.IsPendingApproval(), task.IsFailed(), task.IsDone())
			}
			if task.TaskID == "" || task.Details == "" {
				t.Errorf("fields not decoded: %+v", task)
			}
		})
	}
}

func TestGetTask_NotFound(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 404, fixture(t, "task_404.json")) })
	_, err := c.GetTask(ctx(), "99999999")
	if !IsNotFound(err) {
		t.Fatalf("want 404, got %v", err)
	}
}
