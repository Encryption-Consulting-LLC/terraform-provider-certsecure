// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/http"
	"testing"
)

func TestListAvailableCAs_Fixture(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/available_ca" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		writeJSON(w, 200, fixture(t, "available_ca.json"))
	})
	cas, err := c.ListAvailableCAs(ctx())
	if err != nil {
		t.Fatal(err)
	}
	var msca []AvailableCA
	for _, ca := range cas {
		if ca.Type == "MSCA" {
			msca = append(msca, ca)
		}
	}
	if len(msca) != 3 {
		t.Fatalf("want 3 MSCA CAs, got %+v", msca)
	}
	if msca[2].Name != "Example Issuing CA" || len(msca[2].Connectors) != 1 {
		t.Errorf("unexpected/unsorted entry %+v", msca[2])
	}
	for i := 1; i < len(cas); i++ {
		if cas[i-1].Type > cas[i].Type || (cas[i-1].Type == cas[i].Type && cas[i-1].Name > cas[i].Name) {
			t.Fatalf("not sorted at %d: %+v %+v", i, cas[i-1], cas[i])
		}
	}
}

func TestGetCATemplates_Fixture(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/template/ca" || r.URL.Query().Get("ca") != "Example Issuing CA" {
			t.Errorf("unexpected request %s", r.URL)
		}
		writeJSON(w, 200, fixture(t, "template_ca.json"))
	})
	tmpls, err := c.GetCATemplates(ctx(), "Example Issuing CA")
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpls) != 11 {
		t.Fatalf("got %d templates", len(tmpls))
	}
	var found bool
	for _, tm := range tmpls {
		if tm.FriendlyName == "Web Server" {
			found = true
			if tm.TemplateOID == "" || tm.ValidityPeriod == "" {
				t.Errorf("fields not decoded: %+v", tm)
			}
		}
	}
	if !found {
		t.Error("Web Server template not found")
	}
}

func TestGetCATemplates_Empty(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, fixture(t, "template_ca_empty.json")) })
	tmpls, err := c.GetCATemplates(ctx(), "Other CA")
	if err != nil || len(tmpls) != 0 {
		t.Fatalf("got %v, %v", tmpls, err)
	}
}

func TestListTemplateNames_Fixture(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enrollment/templates" {
			t.Errorf("unexpected request %s", r.URL)
		}
		writeJSON(w, 200, fixture(t, "enrollment_templates.json"))
	})
	names, err := c.ListTemplateNames(ctx(), "Example Issuing CA")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range names {
		found = found || n == "WebServer"
	}
	if !found || len(names) != 11 {
		t.Errorf("WebServer not in %v", names)
	}
	none, err := c.ListTemplateNames(ctx(), "Unknown CA")
	if err != nil || none == nil || len(none) != 0 {
		t.Errorf("unknown CA: got %v, %v; want empty non-nil list", none, err)
	}
}

func TestGetInventoryCertDetails(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("number") == "00" {
			writeJSON(w, 404, fixture(t, "inventory_cert_details_404.json"))
			return
		}
		if q.Get("ca") != "Example Issuing CA" || q.Get("number") != "3400033ba9" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
		writeJSON(w, 200, fixture(t, "inventory_cert_details.json"))
	})
	d, err := c.GetInventoryCertDetails(ctx(), "Example Issuing CA", "3400033ba9")
	if err != nil {
		t.Fatal(err)
	}
	if d["Certificate Template"] != "WebServer" {
		t.Errorf("unexpected details: %v", d["Certificate Template"])
	}
	_, err = c.GetInventoryCertDetails(ctx(), "Example Issuing CA", "00")
	if !IsNotFound(err) {
		t.Fatalf("want 404, got %v", err)
	}
}
