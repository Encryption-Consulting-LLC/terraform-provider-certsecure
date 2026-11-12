// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Encryption-Consulting-LLC/terraform-provider-certsecure/internal/client"
)

const (
	defaultCreateTimeout = 5 * time.Minute
	defaultUpdateTimeout = 5 * time.Minute
	defaultDeleteTimeout = 5 * time.Minute
)

// Poll intervals while waiting for issuance. Variables so tests can shorten them.
var (
	pollInitialInterval = 2 * time.Second
	pollMaxInterval     = 15 * time.Second
)

// now is the clock used to decide whether a certificate is inside its early
// renewal window. A variable so tests can move it.
var now = time.Now

// privateRenewalCSR is the private state key holding the SHA-256 of the CSR a
// pending renewal was submitted with.
const privateRenewalCSR = "pending_renewal_csr_sha256"

// privateIssuanceFailed is the private state key set when a resumed first
// issuance ended without a usable certificate (denied, failed, wrong key), so
// the next plan replaces it with a new request instead of resuming it again.
const privateIssuanceFailed = "issuance_failed"

var (
	_ resource.Resource                     = &certificateResource{}
	_ resource.ResourceWithConfigure        = &certificateResource{}
	_ resource.ResourceWithImportState      = &certificateResource{}
	_ resource.ResourceWithConfigValidators = &certificateResource{}
	_ resource.ResourceWithModifyPlan       = &certificateResource{}
)

// NewCertificateResource returns the certsecure_certificate resource.
func NewCertificateResource() resource.Resource {
	return &certificateResource{}
}

type certificateResource struct {
	client *client.Client
}

type certificateModel struct {
	ID                      types.String   `tfsdk:"id"`
	CSRPEM                  types.String   `tfsdk:"csr_pem"`
	CAName                  types.String   `tfsdk:"ca_name"`
	Template                types.String   `tfsdk:"template"`
	OwnerEmail              types.String   `tfsdk:"owner_email"`
	SubjectAlternativeNames *sanModel      `tfsdk:"subject_alternative_names"`
	OverrideCSRSANs         types.Bool     `tfsdk:"override_csr_sans"`
	Tags                    types.List     `tfsdk:"tags"`
	Notes                   types.String   `tfsdk:"notes"`
	EnrollmentID            types.Int64    `tfsdk:"enrollment_id"`
	TaskID                  types.String   `tfsdk:"task_id"`
	SerialNumber            types.String   `tfsdk:"serial_number"`
	CertificatePEM          types.String   `tfsdk:"certificate_pem"`
	ChainPEM                types.String   `tfsdk:"chain_pem"`
	NotBefore               types.String   `tfsdk:"not_before"`
	NotAfter                types.String   `tfsdk:"not_after"`
	Status                  types.String   `tfsdk:"status"`
	EarlyRenewalHours       types.Int64    `tfsdk:"early_renewal_hours"`
	PendingRenewalTaskID    types.String   `tfsdk:"pending_renewal_task_id"`
	RevokeOnDestroy         types.Bool     `tfsdk:"revoke_on_destroy"`
	WaitForApproval         types.Bool     `tfsdk:"wait_for_approval"`
	Timeouts                timeouts.Value `tfsdk:"timeouts"`
}

type sanModel struct {
	DNS   types.List `tfsdk:"dns"`
	IP    types.List `tfsdk:"ip"`
	Email types.List `tfsdk:"email"`
	URI   types.List `tfsdk:"uri"`
}

func (r *certificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *certificateResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replaceStr := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	keepStr := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	sanList := func(desc string, kind sanKind) schema.ListAttribute {
		return schema.ListAttribute{
			MarkdownDescription: desc,
			ElementType:         types.StringType,
			Optional:            true,
			Validators:          []validator.List{sanValidator{kind: kind}, listvalidator.UniqueValues()},
			PlanModifiers:       []planmodifier.List{listplanmodifier.RequiresReplace()},
		}
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Submits a certificate signing request (CSR) to a CA and template through CertSecure, " +
			"and returns the issued certificate and its chain. Changing `csr_pem`, or reaching the `early_renewal_hours` " +
			"window, renews the certificate in place with the CSR from the configuration. Changing any other argument " +
			"issues a new certificate. With `revoke_on_destroy`, destroying the resource revokes the certificate.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The CertSecure enrollment ID (same value as `enrollment_id`, as a string).",
				Computed:            true,
				PlanModifiers:       keepStr,
			},
			"csr_pem": schema.StringAttribute{
				MarkdownDescription: "PEM-encoded PKCS#10 certificate signing request, for example `tls_cert_request.example.cert_request_pem`. " +
					"Validated at plan time when known. Changing it renews the certificate in place with the new CSR, " +
					"for the same key or a new one.",
				Required:   true,
				Validators: []validator.String{csrValidator{}},
			},
			"ca_name": schema.StringAttribute{
				MarkdownDescription: "Name of the CA in CertSecure, as listed by the `certsecure_cas` data source.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
				PlanModifiers:       replaceStr,
			},
			"template": schema.StringAttribute{
				MarkdownDescription: "Certificate template name, as listed in the `names` attribute of the `certsecure_templates` data source " +
					"(for Microsoft CA this is the template name, e.g. `WebServer`, not the display name `Web Server`).",
				Required:      true,
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
				PlanModifiers: replaceStr,
			},
			"owner_email": schema.StringAttribute{
				MarkdownDescription: "Email address of the certificate owner, recorded in CertSecure and used for notifications.",
				Optional:            true,
				Validators:          []validator.String{emailValidator{}},
				PlanModifiers:       replaceStr,
			},
			"override_csr_sans": schema.BoolAttribute{
				MarkdownDescription: "When `true`, the certificate gets only the SANs in `subject_alternative_names`, replacing those in the CSR. " +
					"When `false` (the default), they are added to the CSR's SANs. Requires `subject_alternative_names`.",
				Optional:      true,
				Computed:      true,
				Default:       booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"tags": schema.ListAttribute{
				MarkdownDescription: "Tags recorded on the certificate in CertSecure. Changing tags issues a new certificate.",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers:       []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"notes": schema.StringAttribute{
				MarkdownDescription: "Additional notes recorded with the request in CertSecure.",
				Optional:            true,
				PlanModifiers:       replaceStr,
			},
			"enrollment_id": schema.Int64Attribute{
				MarkdownDescription: "CertSecure enrollment ID (`eid`). Use it to find, approve, or revoke the certificate in CertSecure.",
				Computed:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"task_id": schema.StringAttribute{
				MarkdownDescription: "CertSecure task ID of the enrollment request. Not available for imported certificates.",
				Computed:            true,
				PlanModifiers:       keepStr,
			},
			"serial_number": schema.StringAttribute{
				MarkdownDescription: "Certificate serial number as lowercase hexadecimal, parsed from `certificate_pem`.",
				Computed:            true,
				PlanModifiers:       keepStr,
			},
			"certificate_pem": schema.StringAttribute{
				MarkdownDescription: "The issued certificate, PEM encoded.",
				Computed:            true,
				PlanModifiers:       keepStr,
			},
			"chain_pem": schema.StringAttribute{
				MarkdownDescription: "The issuing CA chain as concatenated PEM certificates, issuer first (the certificate's issuer, then its issuer, up to the root). " +
					"Does not include the certificate itself.",
				Computed:      true,
				PlanModifiers: keepStr,
			},
			"not_before": schema.StringAttribute{
				MarkdownDescription: "Start of the certificate validity period (RFC 3339), parsed from `certificate_pem`.",
				Computed:            true,
				PlanModifiers:       keepStr,
			},
			"not_after": schema.StringAttribute{
				MarkdownDescription: "End of the certificate validity period (RFC 3339), parsed from `certificate_pem`.",
				Computed:            true,
				PlanModifiers:       keepStr,
			},
			"status": schema.StringAttribute{
				MarkdownDescription: "Enrollment status reported by CertSecure, e.g. `active`, `pending`, `requested` (awaiting approval), " +
					"`denied`, `failed`, or `revoked`. Refreshed on every read.",
				Computed:      true,
				PlanModifiers: keepStr,
			},
			"early_renewal_hours": schema.Int64Attribute{
				MarkdownDescription: "Renew the certificate in place when it expires within this many hours. The renewal " +
					"happens on the first plan and apply inside the window, with the CSR from the configuration. " +
					"Defaults to `0` (disabled).",
				Optional:   true,
				Computed:   true,
				Default:    int64default.StaticInt64(0),
				Validators: []validator.Int64{int64validator.AtLeast(0)},
			},
			"revoke_on_destroy": schema.BoolAttribute{
				MarkdownDescription: "When `true`, destroying the resource revokes the certificate in CertSecure and waits until " +
					"the revocation completes. Defaults to `false`: destroy only removes the certificate from Terraform state and it " +
					"stays valid. Apply the value before destroying, like any deletion setting. A replacement (for example after " +
					"changing `template`) also revokes the old certificate: set `lifecycle { create_before_destroy = true }` so the " +
					"new certificate reaches its consumers before the old one is revoked.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"wait_for_approval": schema.BoolAttribute{
				MarkdownDescription: "When `true`, an apply whose request awaits approval in CertSecure keeps waiting until " +
					"the request is approved and issued, denied, or the `create` (or, for renewals, `update`) timeout " +
					"expires. Set a timeout long enough for your approval process. Defaults to `false`: the apply stops " +
					"with an error as soon as the request awaits approval, and a later apply resumes it. The provider never " +
					"approves or denies requests.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"pending_renewal_task_id": schema.StringAttribute{
				MarkdownDescription: "CertSecure task ID of a renewal that was submitted but has not completed, for example " +
					"because it awaits approval. The next apply resumes this request instead of submitting a new one. " +
					"Empty when no renewal is in progress.",
				Computed:      true,
				PlanModifiers: keepStr,
			},
		},
		Blocks: map[string]schema.Block{
			"subject_alternative_names": schema.SingleNestedBlock{
				MarkdownDescription: "Subject alternative names to request in addition to (or, with `override_csr_sans`, instead of) those in the CSR. " +
					"Whether the CA honors requested SANs depends on its template and policy settings.",
				Attributes: map[string]schema.Attribute{
					"dns":   sanList("DNS names.", sanDNS),
					"ip":    sanList("IPv4 or IPv6 addresses.", sanIP),
					"email": sanList("Email addresses (RFC 822 names).", sanEmail),
					"uri":   sanList("URIs, e.g. `spiffe://example.com/app`.", sanURI),
				},
				PlanModifiers: []planmodifier.Object{objectplanmodifier.RequiresReplace()},
			},
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Update: true, Delete: true}),
		},
	}
}

func (r *certificateResource) ConfigValidators(context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{overrideRequiresSANs{}}
}

func (r *certificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *providerData, got %T", req.ProviderData))
		return
	}
	r.client = data.client
}

func (r *certificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan certificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, defaultCreateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	csr, err := parseCSR(plan.CSRPEM.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("csr_pem"), "Invalid CSR", err.Error())
		return
	}

	enrollReq, diags := buildEnrollRequest(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Submitted exactly once. Never retried: a retry could issue a duplicate certificate.
	enrolled, err := r.client.EnrollCSR(ctx, enrollReq)
	if err != nil {
		summary, detail := describeAPIError(err)
		if !client.IsBadRequest(err) && !client.IsUnauthorized(err) && !client.IsForbidden(err) {
			detail += "\n\nThe request may still have been accepted by CertSecure. Check the CertSecure task list " +
				"for a certificate request for this CSR before running apply again, to avoid issuing a duplicate."
		}
		resp.Diagnostics.AddError("Error submitting certificate request: "+summary, detail)
		return
	}
	if enrolled.TaskID == "" && enrolled.EnrollmentID == 0 {
		resp.Diagnostics.AddError("Unrecognized CertSecure response",
			"CertSecure accepted the certificate request but returned neither a task ID nor an enrollment ID, "+
				"so the provider cannot track it. Check CertSecure for the request. Response: "+enrolled.RawBody)
		return
	}
	tflog.Info(ctx, "Certificate request submitted", map[string]any{"task_id": enrolled.TaskID, "enrollment_id": enrolled.EnrollmentID})

	plan.TaskID = types.StringValue(enrolled.TaskID)
	if enrolled.TaskID == "" {
		plan.TaskID = types.StringNull()
	}
	plan.PendingRenewalTaskID = types.StringNull()

	// As soon as the enrollment ID is known, save it so it can never be lost,
	// even if a later step fails (the resource is then marked tainted, and
	// untainting it lets the next apply resume this request).
	saved := false
	saveEID := func(eid int64) {
		saved = true
		plan.ID = types.StringValue(strconv.FormatInt(eid, 10))
		plan.EnrollmentID = types.Int64Value(eid)
		partial := plan
		partial.SerialNumber = types.StringNull()
		partial.CertificatePEM = types.StringNull()
		partial.ChainPEM = types.StringNull()
		partial.NotBefore = types.StringNull()
		partial.NotAfter = types.StringNull()
		partial.Status = types.StringValue("pending")
		resp.Diagnostics.Append(resp.State.Set(ctx, &partial)...)
	}

	result, waitErr := r.waitForCertificate(ctx, enrolled, csr, saveEID, plan.WaitForApproval.ValueBool())
	if waitErr != nil {
		resp.Diagnostics.AddError(waitErr.summary, waitErr.detail+createAdvice(waitErr.kind, saved))
		return
	}

	plan.Status = types.StringValue(result.status)
	setCertificateFields(&plan, result.leaf, result.chain)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// issuancePending reports whether state holds a first issuance that has no
// certificate yet: a request awaiting approval, or one an earlier apply
// stopped waiting for. Imported records (no csr_pem) are excluded.
func issuancePending(state *certificateModel) bool {
	return !state.CSRPEM.IsNull() && valueOr(state.CertificatePEM, "") == ""
}

func buildEnrollRequest(ctx context.Context, plan *certificateModel) (client.EnrollCSRRequest, diag.Diagnostics) {
	var diags diag.Diagnostics
	req := client.EnrollCSRRequest{
		CSR:             plan.CSRPEM.ValueString(),
		CA:              plan.CAName.ValueString(),
		Template:        plan.Template.ValueString(),
		OverrideCSRSANs: plan.OverrideCSRSANs.ValueBool(),
		AdditionalNotes: plan.Notes.ValueString(),
	}
	if e := plan.OwnerEmail.ValueString(); e != "" {
		req.Email = []string{e}
	}
	if !plan.Tags.IsNull() {
		diags.Append(plan.Tags.ElementsAs(ctx, &req.Tags, false)...)
	}
	if s := plan.SubjectAlternativeNames; s != nil {
		var sans client.SANs
		diags.Append(s.DNS.ElementsAs(ctx, &sans.DNS, false)...)
		diags.Append(s.IP.ElementsAs(ctx, &sans.IP, false)...)
		diags.Append(s.Email.ElementsAs(ctx, &sans.Email, false)...)
		diags.Append(s.URI.ElementsAs(ctx, &sans.URI, false)...)
		req.SANAttributes = sans.Entries()
	}
	return req, diags
}

type issuedCertificate struct {
	eid    int64
	leaf   *x509.Certificate
	chain  []*x509.Certificate
	status string
}

// waitErrorKind classifies why waitForCertificate stopped, so Create and
// Update can say what the next apply does.
type waitErrorKind int

const (
	waitErrOther       waitErrorKind = iota // API or download error; the request may still complete
	waitErrFailed                           // the task ended in ERROR (denied, CA error)
	waitErrPending                          // waiting for approval
	waitErrTimeout                          // still processing when the timeout expired
	waitErrKeyMismatch                      // the certificate is not for the submitted CSR
)

type createError struct {
	kind            waitErrorKind
	summary, detail string
}

// waitForCertificate follows an asynchronous CertSecure enrollment until the
// certificate can be downloaded, the request fails, it turns out to need
// approval (unless waitApproval), or ctx expires. saveEID is called once when
// the enrollment ID becomes known.
func (r *certificateResource) waitForCertificate(ctx context.Context, enrolled *client.EnrollCSRResponse, csr *x509.CertificateRequest, saveEID func(int64), waitApproval bool) (*issuedCertificate, *createError) {
	taskID := enrolled.TaskID
	eid := enrolled.EnrollmentID
	if eid != 0 {
		saveEID(eid)
	}

	ids := func() string {
		parts := []string{}
		if eid != 0 {
			parts = append(parts, fmt.Sprintf("enrollment ID (eid) %d", eid))
		}
		if taskID != "" {
			parts = append(parts, "task ID "+taskID)
		}
		return strings.Join(parts, ", ")
	}

	var lastState string
	// awaitingApproval tells whether the latest poll saw the request awaiting
	// approval (only with waitApproval; otherwise that ends the wait).
	var awaitingApproval, loggedApproval bool
	pending := func(details string) *createError {
		if !waitApproval {
			return pendingApprovalError(ids(), details)
		}
		if !loggedApproval {
			loggedApproval = true
			tflog.Info(ctx, "Certificate request awaits approval, waiting", map[string]any{"task_id": taskID, "enrollment_id": eid})
		}
		awaitingApproval = true
		return nil
	}
	interval := pollInitialInterval
	for {
		if taskID != "" {
			// 1. Task status: detects approval waits and failures.
			task, err := r.client.GetTask(ctx, taskID)
			if client.IsUnauthorized(err) || client.IsForbidden(err) {
				summary, detail := describeAPIError(err)
				return nil, &createError{summary: "Error checking certificate request: " + summary, detail: detail + "\n\nRequest: " + ids() + "."}
			}
			if err != nil {
				tflog.Debug(ctx, "Task lookup failed, will retry", map[string]any{"task_id": taskID, "error": err.Error()})
			} else {
				lastState = fmt.Sprintf("task %s: %s (%s)", task.StatusInfo, task.Status, task.Details)
				awaitingApproval = false
			}

			// 2. Resolve the enrollment ID, which CertSecure assigns shortly
			// after the task is created. Done before acting on a terminal task
			// state so errors always report it.
			if eid == 0 && (err != nil || !strings.EqualFold(task.StatusInfo, client.TaskInitialized)) {
				if d, err := r.client.GetEnrollmentDetailsByTaskID(ctx, taskID); err == nil && d.EnrollmentID > 0 {
					eid = d.EnrollmentID
					tflog.Info(ctx, "Enrollment ID assigned", map[string]any{"task_id": taskID, "enrollment_id": eid})
					saveEID(eid)
				}
			}

			if err == nil && task.IsFailed() {
				return nil, &createError{
					kind:    waitErrFailed,
					summary: "Certificate request failed in CertSecure",
					detail:  fmt.Sprintf("CertSecure reported %q: %s\n\nRequest: %s.", task.Status, task.Details, ids()),
				}
			}
			if err == nil && task.IsPendingApproval() {
				if e := pending(task.Details); e != nil {
					return nil, e
				}
			}
		}

		// 3. Enrollment status and certificate download.
		if eid != 0 {
			d, err := r.client.GetEnrollmentDetails(ctx, eid)
			switch {
			case err == nil:
				lastState = fmt.Sprintf("enrollment status %q, certificate available: %t", d.Status, d.CertAvailable)
				if strings.EqualFold(d.Status, "requested") {
					if e := pending(""); e != nil {
						return nil, e
					}
				}
				if d.CertAvailable {
					return r.fetchIssued(ctx, eid, csr, d.Status, ids())
				}
			case client.IsUnauthorized(err) || client.IsForbidden(err):
				summary, detail := describeAPIError(err)
				return nil, &createError{summary: "Error checking certificate request: " + summary, detail: detail + "\n\nRequest: " + ids() + "."}
			default:
				tflog.Debug(ctx, "Enrollment lookup failed, will retry", map[string]any{"enrollment_id": eid, "error": err.Error()})
			}
		}

		select {
		case <-ctx.Done():
			if awaitingApproval {
				return nil, &createError{
					kind:    waitErrPending,
					summary: "Timed out waiting for approval",
					detail: "The certificate request still awaited approval in CertSecure when the timeout expired." +
						"\n\nRequest: " + ids() + ".",
				}
			}
			detail := "The certificate was not available before the timeout expired."
			if lastState != "" {
				detail += " Last known state: " + lastState + "."
			}
			if ids() != "" {
				detail += "\n\nRequest: " + ids() + ". Use these to find, approve, or revoke the request in CertSecure."
			}
			return nil, &createError{kind: waitErrTimeout, summary: "Timed out waiting for certificate issuance", detail: detail}
		case <-time.After(interval):
		}
		interval = min(interval*2, pollMaxInterval)
	}
}

func pendingApprovalError(ids, details string) *createError {
	detail := "The certificate template requires approval in CertSecure."
	if details != "" {
		detail += " CertSecure: " + details + "."
	}
	detail += "\n\nRequest: " + ids + "."
	return &createError{kind: waitErrPending, summary: "Certificate request requires approval", detail: detail}
}

// createAdvice says what the next apply does after Create stopped with kind.
// saved tells whether the request was recorded in state, so it can be resumed.
func createAdvice(kind waitErrorKind, saved bool) string {
	if kind == waitErrFailed || kind == waitErrKeyMismatch {
		return ""
	}
	var advice string
	switch kind {
	case waitErrPending:
		advice = " Approve or deny it in CertSecure."
	case waitErrTimeout:
		advice = " Increase timeouts.create if issuance is slow."
	}
	if !saved {
		return advice + " Running apply again submits a new certificate request."
	}
	return advice + "\n\nThe request is saved in state, and Terraform marks the resource as tainted, so the next apply " +
		"would submit a new request. To resume this request instead, run terraform untaint with the resource address, " +
		"then apply again: the provider waits for this request and does not submit a new one."
}

// fetchIssued downloads the certificate and chain for eid and checks that the
// certificate belongs to the submitted CSR.
func (r *certificateResource) fetchIssued(ctx context.Context, eid int64, csr *x509.CertificateRequest, status, ids string) (*issuedCertificate, *createError) {
	leaf, chain, err := r.downloadCertificate(ctx, eid)
	if err != nil {
		summary, detail := describeAPIError(err)
		return nil, &createError{
			summary: "Certificate issued but could not be downloaded: " + summary,
			detail:  detail + "\n\nRequest: " + ids + ". The certificate exists in CertSecure; download or revoke it there.",
		}
	}
	if csr != nil && !publicKeysEqual(leaf.PublicKey, csr.PublicKey) {
		return nil, &createError{
			kind:    waitErrKeyMismatch,
			summary: "Downloaded certificate does not match the CSR",
			detail: fmt.Sprintf("The certificate CertSecure returned (serial %s, subject %q) does not contain the public key of the submitted CSR.\n\nRequest: %s.",
				client.SerialHex(leaf), leaf.Subject.String(), ids),
		}
	}
	return &issuedCertificate{eid: eid, leaf: leaf, chain: chain, status: status}, nil
}

// downloadCertificate returns the leaf certificate and its chain (issuer first).
func (r *certificateResource) downloadCertificate(ctx context.Context, eid int64) (*x509.Certificate, []*x509.Certificate, error) {
	leaf, err := r.client.DownloadCert(ctx, eid)
	if err != nil {
		return nil, nil, err
	}
	bundle, err := r.client.DownloadChain(ctx, eid)
	if err != nil {
		return nil, nil, fmt.Errorf("downloading certificate chain: %w", err)
	}
	return leaf, client.BuildChain(leaf, bundle), nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

func setCertificateFields(m *certificateModel, leaf *x509.Certificate, chain []*x509.Certificate) {
	m.CertificatePEM = types.StringValue(client.EncodePEM(leaf))
	if len(chain) > 0 {
		m.ChainPEM = types.StringValue(client.EncodePEM(chain...))
	} else {
		m.ChainPEM = types.StringValue("")
	}
	m.SerialNumber = types.StringValue(client.SerialHex(leaf))
	m.NotBefore = types.StringValue(leaf.NotBefore.UTC().Format(time.RFC3339))
	m.NotAfter = types.StringValue(leaf.NotAfter.UTC().Format(time.RFC3339))
}

func (r *certificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state certificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	eid := state.EnrollmentID.ValueInt64()
	if state.EnrollmentID.IsNull() || state.EnrollmentID.IsUnknown() {
		n, err := strconv.ParseInt(state.ID.ValueString(), 10, 64)
		if err != nil {
			resp.Diagnostics.AddError("Invalid resource ID", fmt.Sprintf("%q is not a CertSecure enrollment ID.", state.ID.ValueString()))
			return
		}
		eid = n
		state.EnrollmentID = types.Int64Value(eid)
	}

	d, err := r.client.GetEnrollmentDetails(ctx, eid)
	if client.IsNotFound(err) {
		tflog.Warn(ctx, "Enrollment no longer exists in CertSecure; removing from state", map[string]any{"enrollment_id": eid})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		summary, detail := describeAPIError(err)
		resp.Diagnostics.AddError("Error reading certificate enrollment: "+summary, detail)
		return
	}

	state.ID = types.StringValue(strconv.FormatInt(eid, 10))
	state.Status = types.StringValue(d.Status)

	// Imported resources: populate what the API returns so a matching
	// configuration does not plan a replacement.
	if state.CAName.IsNull() && d.CertificateAuthority != "" {
		state.CAName = types.StringValue(d.CertificateAuthority)
	}
	if state.Template.IsNull() && d.Template != "" {
		state.Template = types.StringValue(d.Template)
	}
	if state.OverrideCSRSANs.IsNull() {
		state.OverrideCSRSANs = types.BoolValue(false)
	}
	if state.RevokeOnDestroy.IsNull() || state.RevokeOnDestroy.IsUnknown() {
		state.RevokeOnDestroy = types.BoolValue(false)
	}
	if state.WaitForApproval.IsNull() || state.WaitForApproval.IsUnknown() {
		state.WaitForApproval = types.BoolValue(false)
	}
	if state.EarlyRenewalHours.IsNull() || state.EarlyRenewalHours.IsUnknown() {
		state.EarlyRenewalHours = types.Int64Value(0)
	}
	if state.TaskID.IsUnknown() {
		state.TaskID = types.StringNull()
	}
	if state.PendingRenewalTaskID.IsUnknown() {
		state.PendingRenewalTaskID = types.StringNull()
	}

	// Fill in the certificate of an imported record once it is available. A
	// pending first issuance is completed by Update instead, which checks the
	// certificate against the CSR.
	if state.CSRPEM.IsNull() && valueOr(state.CertificatePEM, "") == "" && d.CertAvailable {
		leaf, chain, err := r.downloadCertificate(ctx, eid)
		if err != nil {
			summary, detail := describeAPIError(err)
			resp.Diagnostics.AddWarning("Could not download certificate: "+summary, detail)
		} else {
			setCertificateFields(&state, leaf, chain)
		}
	}
	nullIfUnknown(&state.SerialNumber, &state.CertificatePEM, &state.ChainPEM, &state.NotBefore, &state.NotAfter)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func nullIfUnknown(vals ...*types.String) {
	for _, v := range vals {
		if v.IsUnknown() {
			*v = types.StringNull()
		}
	}
}

// ModifyPlan plans an in-place renewal when csr_pem changes, the certificate
// is inside its early_renewal_hours window, or an earlier renewal is still
// pending. A renewal marks the certificate attributes unknown; Update then
// renews through CertSecure.
func (r *certificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Create, destroy, and replacement need no renewal.
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() || len(resp.RequiresReplace) > 0 {
		return
	}
	var state, plan certificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if issuancePending(&state) {
		failed, diags := req.Private.GetKey(ctx, privateIssuanceFailed)
		resp.Diagnostics.Append(diags...)
		r.planPendingIssuance(ctx, &state, &plan, len(failed) > 0, resp)
		return
	}

	if w := renewalWindowWarning(&state, &plan); w != "" {
		resp.Diagnostics.AddAttributeWarning(path.Root("early_renewal_hours"), "Renewal window covers the whole certificate lifetime", w)
	}

	reason := renewalReason(&state, &plan)
	if reason == "" {
		return
	}
	tflog.Info(ctx, "Planning in-place certificate renewal", map[string]any{"enrollment_id": state.EnrollmentID.ValueInt64(), "reason": reason})
	for _, name := range []string{"id", "task_id", "serial_number", "certificate_pem", "chain_pem", "not_before", "not_after", "status", "pending_renewal_task_id"} {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(name), types.StringUnknown())...)
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("enrollment_id"), types.Int64Unknown())...)
}

// planPendingIssuance plans what happens to a first issuance with no
// certificate yet (see issuancePending): Update resumes the request, or, if
// it can no longer produce the configured certificate, the resource is
// replaced and a new request is submitted.
func (r *certificateResource) planPendingIssuance(ctx context.Context, state, plan *certificateModel, failed bool, resp *resource.ModifyPlanResponse) {
	eid, taskID := state.EnrollmentID.ValueInt64(), valueOr(state.TaskID, "unknown")
	var replace string
	switch status := strings.ToLower(state.Status.ValueString()); {
	case status == "denied" || status == "failed":
		replace = fmt.Sprintf("it is %s in CertSecure", status)
	case failed:
		replace = "it ended without a certificate for the CSR"
	case plan.CSRPEM.IsUnknown() || !sameCSR(state.CSRPEM.ValueString(), plan.CSRPEM.ValueString()):
		replace = "csr_pem changed"
	}

	for _, name := range []string{"serial_number", "certificate_pem", "chain_pem", "not_before", "not_after", "status"} {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(name), types.StringUnknown())...)
	}
	if replace == "" {
		tflog.Info(ctx, "Planning to resume pending certificate request", map[string]any{"enrollment_id": eid, "task_id": taskID})
		return
	}
	resp.RequiresReplace.Append(path.Root("certificate_pem"))
	resp.Diagnostics.AddWarning("Pending certificate request is replaced",
		fmt.Sprintf("The certificate request with enrollment ID (eid) %d, task ID %s, has no certificate yet and is not resumed "+
			"because %s. The apply submits a new request. If the old request still awaits approval, deny it in CertSecure.",
			eid, taskID, replace))
}

// renewalReason returns why the certificate in state must be renewed for
// plan, or "" if it need not be.
func renewalReason(state, plan *certificateModel) string {
	if id := state.PendingRenewalTaskID.ValueString(); id != "" {
		return "renewal task " + id + " is still pending"
	}
	if plan.CSRPEM.IsUnknown() {
		return "csr_pem is not known until apply"
	}
	if state.CSRPEM.IsNull() {
		// Imported: the CSR was never recorded. Renew only if the configured
		// CSR is for a different key than the certificate.
		csr, err := parseCSR(plan.CSRPEM.ValueString())
		cert, certErr := parseCertificatePEM(state.CertificatePEM.ValueString())
		if err == nil && certErr == nil && publicKeysEqual(cert.PublicKey, csr.PublicKey) {
			return ""
		}
		return "csr_pem is for a different key than the imported certificate"
	}
	if !sameCSR(state.CSRPEM.ValueString(), plan.CSRPEM.ValueString()) {
		return "csr_pem changed"
	}
	if hours := plan.EarlyRenewalHours; !hours.IsUnknown() && hours.ValueInt64() > 0 {
		if notAfter, err := time.Parse(time.RFC3339, state.NotAfter.ValueString()); err == nil &&
			!now().Before(notAfter.Add(-time.Duration(hours.ValueInt64())*time.Hour)) {
			return "the certificate expires within early_renewal_hours"
		}
	}
	return ""
}

// renewalWindowWarning returns a warning when early_renewal_hours is at least
// the certificate's lifetime, so every apply would renew it.
func renewalWindowWarning(state, plan *certificateModel) string {
	hours := plan.EarlyRenewalHours
	if hours.IsUnknown() || hours.ValueInt64() <= 0 {
		return ""
	}
	notBefore, err1 := time.Parse(time.RFC3339, state.NotBefore.ValueString())
	notAfter, err2 := time.Parse(time.RFC3339, state.NotAfter.ValueString())
	window := time.Duration(hours.ValueInt64()) * time.Hour
	if err1 != nil || err2 != nil || window < notAfter.Sub(notBefore) {
		return ""
	}
	return fmt.Sprintf("early_renewal_hours (%d) is at least the certificate's lifetime (%s to %s), so every apply renews "+
		"the certificate. Use a window shorter than the validity period.", hours.ValueInt64(), state.NotBefore.ValueString(), state.NotAfter.ValueString())
}

// sameCSR reports whether two PEM CSRs encode the same request, ignoring
// formatting differences.
func sameCSR(a, b string) bool {
	da, _ := pem.Decode([]byte(strings.TrimSpace(a)))
	db, _ := pem.Decode([]byte(strings.TrimSpace(b)))
	if da == nil || db == nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return bytes.Equal(da.Bytes, db.Bytes)
}

func parseCertificatePEM(s string) (*x509.Certificate, error) {
	certs, err := client.ParseCertificates([]byte(s))
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// csrFingerprint identifies the CSR a pending renewal was submitted with.
func csrFingerprint(csr *x509.CertificateRequest) []byte {
	sum := sha256.Sum256(csr.Raw)
	b, _ := json.Marshal(hex.EncodeToString(sum[:]))
	return b
}

func (r *certificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state certificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// No renewal planned: only settings (timeouts, early_renewal_hours) or the
	// formatting of csr_pem changed.
	if !plan.CertificatePEM.IsUnknown() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, defaultUpdateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	csr, err := parseCSR(plan.CSRPEM.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("csr_pem"), "Invalid CSR", err.Error())
		return
	}
	if issuancePending(&state) {
		r.resumeIssuance(ctx, csr, &plan, &state, resp)
		return
	}
	eid := state.EnrollmentID.ValueInt64()
	fingerprint := csrFingerprint(csr)

	// While the renewal is in flight, state keeps the previous certificate
	// (still in use downstream) and records the renewal task, and private
	// state the CSR it was submitted with. Keeping the old csr_pem makes the
	// next plan show the renewal again, so it can resume.
	inFlight := state
	inFlight.Timeouts = plan.Timeouts
	inFlight.EarlyRenewalHours = plan.EarlyRenewalHours
	inFlight.RevokeOnDestroy = plan.RevokeOnDestroy
	inFlight.WaitForApproval = plan.WaitForApproval
	saveInFlight := func(taskID string, submittedCSR []byte) {
		inFlight.PendingRenewalTaskID = types.StringNull()
		if taskID != "" {
			inFlight.PendingRenewalTaskID = types.StringValue(taskID)
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &inFlight)...)
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, privateRenewalCSR, submittedCSR)...)
	}

	taskID := state.PendingRenewalTaskID.ValueString()
	if taskID != "" {
		// Resume the earlier renewal instead of submitting another one.
		submitted, diags := req.Private.GetKey(ctx, privateRenewalCSR)
		resp.Diagnostics.Append(diags...)
		if len(submitted) > 0 && !bytes.Equal(submitted, fingerprint) {
			saveInFlight(taskID, submitted)
			resp.Diagnostics.AddError("A renewal for a different CSR is still pending",
				fmt.Sprintf("Renewal task %s for enrollment ID (eid) %d was submitted with a different CSR than the one now in "+
					"the configuration. To avoid two renewals in flight, the provider does not submit another one. Approve or "+
					"deny task %s in CertSecure, or restore the previous CSR in the configuration, then run apply again.", taskID, eid, taskID))
			return
		}
		if _, err := r.client.GetTask(ctx, taskID); client.IsNotFound(err) {
			saveInFlight("", nil)
			resp.Diagnostics.AddError("Pending renewal task no longer exists",
				fmt.Sprintf("CertSecure has no task %s, the pending renewal of enrollment ID (eid) %d. The previous certificate "+
					"is still in state. Running apply again submits a new renewal.", taskID, eid))
			return
		}
		tflog.Info(ctx, "Resuming pending certificate renewal", map[string]any{"enrollment_id": eid, "task_id": taskID})
	} else {
		enrollReq, diags := buildEnrollRequest(ctx, &plan)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		// Submitted exactly once. Never retried: a retry queues a second renewal.
		renewed, err := r.client.RenewCSR(ctx, client.RenewCSRRequest{EnrollCSRRequest: enrollReq, EID: eid})
		if err != nil {
			saveInFlight("", nil)
			summary, detail := describeRenewError(err, eid)
			resp.Diagnostics.AddError("Error submitting certificate renewal: "+summary, detail)
			return
		}
		if renewed.TaskID == "" {
			saveInFlight("", nil)
			resp.Diagnostics.AddError("Unrecognized CertSecure response",
				fmt.Sprintf("CertSecure accepted the renewal of enrollment ID (eid) %d but returned no task ID, so the provider "+
					"cannot track it. Check CertSecure for the renewal before running apply again. Response: %s", eid, renewed.RawBody))
			return
		}
		taskID = renewed.TaskID
		tflog.Info(ctx, "Certificate renewal submitted", map[string]any{"enrollment_id": eid, "task_id": taskID})
		saveInFlight(taskID, fingerprint)
	}

	result, waitErr := r.waitForCertificate(ctx, &client.EnrollCSRResponse{TaskID: taskID}, csr, func(int64) {}, plan.WaitForApproval.ValueBool())
	if waitErr != nil {
		summary, advice := waitErr.summary, ""
		switch waitErr.kind {
		case waitErrPending:
			summary = "Certificate renewal requires approval"
			advice = " Approve or deny it in CertSecure, then run apply again: it resumes this renewal and does not submit a new one."
		case waitErrTimeout:
			summary = "Timed out waiting for certificate renewal"
			advice = " Running apply again resumes this renewal and does not submit a new one; increase timeouts.update if issuance is slow."
		case waitErrFailed, waitErrKeyMismatch:
			saveInFlight("", nil)
			advice = " Running apply again submits a new renewal."
		default:
			advice = " Running apply again resumes this renewal."
		}
		kept := fmt.Sprintf(" The previous certificate (enrollment ID %d) is still in state and in use.", eid)
		resp.Diagnostics.AddError(summary, waitErr.detail+kept+advice)
		return
	}

	plan.ID = types.StringValue(strconv.FormatInt(result.eid, 10))
	plan.EnrollmentID = types.Int64Value(result.eid)
	plan.TaskID = types.StringValue(taskID)
	plan.PendingRenewalTaskID = types.StringNull()
	plan.Status = types.StringValue(result.status)
	setCertificateFields(&plan, result.leaf, result.chain)
	tflog.Info(ctx, "Certificate renewed", map[string]any{"previous_enrollment_id": eid, "enrollment_id": result.eid, "task_id": taskID})
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, privateRenewalCSR, nil)...)
}

// resumeIssuance waits for the first issuance recorded in state (see
// issuancePending) instead of submitting a new request.
func (r *certificateResource) resumeIssuance(ctx context.Context, csr *x509.CertificateRequest, plan, state *certificateModel, resp *resource.UpdateResponse) {
	eid, taskID := state.EnrollmentID.ValueInt64(), state.TaskID.ValueString()

	// Until the certificate is downloaded, state keeps the request as it is,
	// with the new settings.
	kept := *state
	kept.Timeouts = plan.Timeouts
	kept.EarlyRenewalHours = plan.EarlyRenewalHours
	kept.RevokeOnDestroy = plan.RevokeOnDestroy
	kept.WaitForApproval = plan.WaitForApproval
	resp.Diagnostics.Append(resp.State.Set(ctx, &kept)...)

	tflog.Info(ctx, "Resuming pending certificate request", map[string]any{"enrollment_id": eid, "task_id": taskID})
	result, waitErr := r.waitForCertificate(ctx, &client.EnrollCSRResponse{TaskID: taskID, EnrollmentID: eid}, csr, func(int64) {}, plan.WaitForApproval.ValueBool())
	if waitErr != nil {
		summary, advice := waitErr.summary, ""
		switch waitErr.kind {
		case waitErrPending:
			advice = " Approve or deny it in CertSecure, then run apply again: it resumes this request and does not submit a new one."
		case waitErrTimeout:
			advice = " Running apply again resumes this request and does not submit a new one; increase timeouts.update if issuance is slow."
		case waitErrFailed, waitErrKeyMismatch:
			resp.Diagnostics.Append(resp.Private.SetKey(ctx, privateIssuanceFailed, []byte("true"))...)
			advice = " The next apply replaces the resource and submits a new request."
		default:
			advice = " Running apply again resumes this request."
		}
		resp.Diagnostics.AddError(summary, waitErr.detail+advice)
		return
	}

	plan.ID = types.StringValue(strconv.FormatInt(result.eid, 10))
	plan.EnrollmentID = types.Int64Value(result.eid)
	plan.Status = types.StringValue(result.status)
	setCertificateFields(plan, result.leaf, result.chain)
	tflog.Info(ctx, "Pending certificate request completed", map[string]any{"enrollment_id": result.eid, "task_id": taskID})
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// describeRenewError maps a renew_csr submission error to a diagnostic.
func describeRenewError(err error, eid int64) (summary, detail string) {
	var apiErr *client.APIError
	msg := err.Error()
	if errors.As(err, &apiErr) && apiErr.Message != "" {
		msg = apiErr.Message
	}
	switch {
	case client.IsNotFound(err):
		return "Certificate no longer exists in CertSecure",
			fmt.Sprintf("CertSecure has no enrollment record with ID (eid) %d, so it cannot be renewed. Run a refresh to remove it "+
				"from state, or use terraform apply -replace to issue a new certificate.\n\n%s", eid, err)
	case client.IsConflict(err):
		return "Certificate is not renewable",
			fmt.Sprintf("CertSecure: %s. Only active and expired certificates can be renewed. Use terraform apply -replace "+
				"to issue a new certificate for enrollment ID (eid) %d instead.\n\n%s", msg, eid, err)
	case client.IsForbidden(err):
		return "Not allowed to renew this certificate",
			fmt.Sprintf("The CertSecure user of the API token needs the Renew Inventory Certificates permission, or must be the owner "+
				"or a watcher of enrollment ID (eid) %d.\n\n%s", eid, err)
	}
	summary, detail = describeAPIError(err)
	if !client.IsBadRequest(err) && !client.IsUnauthorized(err) {
		detail += fmt.Sprintf("\n\nThe renewal may still have been accepted by CertSecure. Check the CertSecure task list for a "+
			"renewal of enrollment ID (eid) %d before running apply again, to avoid a duplicate renewal.", eid)
	}
	return summary, detail
}

func (r *certificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state certificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	eid := state.EnrollmentID.ValueInt64()
	if issuancePending(&state) && !state.RevokeOnDestroy.ValueBool() {
		resp.Diagnostics.AddWarning("Certificate request was NOT cancelled",
			fmt.Sprintf("The certificate request with enrollment ID %s, task ID %s, had no certificate yet and is only removed "+
				"from Terraform state. If it still awaits approval in CertSecure, deny it there; if it was issued meanwhile, "+
				"revoke it there if it is no longer needed.", state.ID.ValueString(), valueOr(state.TaskID, "unknown")))
		return
	}
	if !state.RevokeOnDestroy.ValueBool() || eid <= 0 {
		resp.Diagnostics.AddWarning("Certificate was NOT revoked",
			fmt.Sprintf("revoke_on_destroy is not set, so the certificate is only removed from Terraform state. Certificate with "+
				"enrollment ID %s (serial %s) is still valid in CertSecure; revoke it there if it is no longer needed.",
				state.ID.ValueString(), valueOr(state.SerialNumber, "unknown")))
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, defaultDeleteTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	if id := state.PendingRenewalTaskID.ValueString(); id != "" {
		resp.Diagnostics.AddWarning("Pending renewal was not cancelled",
			fmt.Sprintf("Renewal task %s of enrollment ID (eid) %d is still open in CertSecure. If it is approved later, its "+
				"certificate is not managed by Terraform; deny it in CertSecure if it is no longer needed.", id, eid))
	}

	// Only active certificates can be revoked; CertSecure answers 404 for any
	// other status, so check first.
	if done, ok := r.revocationDone(ctx, eid, &resp.Diagnostics); !ok || done {
		return
	}

	// Submitted exactly once. Never retried: a retry queues a second revocation.
	taskID, err := r.client.RevokeCert(ctx, eid)
	if client.IsNotFound(err) {
		// No longer active since the check above (expired or revoked meanwhile).
		if done, ok := r.revocationDone(ctx, eid, &resp.Diagnostics); !ok || done {
			return
		}
	}
	if err != nil {
		summary, detail := describeRevokeError(err, eid)
		resp.Diagnostics.AddError("Error revoking certificate: "+summary, detail)
		return
	}
	if taskID == "" {
		resp.Diagnostics.AddError("Unrecognized CertSecure response",
			fmt.Sprintf("CertSecure accepted the revocation of enrollment ID (eid) %d but returned no task ID, so the provider "+
				"cannot follow it. Check the certificate in CertSecure; it is kept in state.", eid))
		return
	}
	tflog.Info(ctx, "Certificate revocation submitted", map[string]any{"enrollment_id": eid, "task_id": taskID})

	if waitErr := r.waitForRevocation(ctx, eid, taskID); waitErr != nil {
		resp.Diagnostics.AddError(waitErr.summary, waitErr.detail)
		return
	}
	tflog.Info(ctx, "Certificate revoked", map[string]any{"enrollment_id": eid, "task_id": taskID})
}

// revocationDone reads the status of eid before a revocation. done is true
// when there is nothing (left) to revoke: the certificate is revoked, expired,
// gone, or in a state that cannot be revoked (reported as a warning). ok is
// false if the status could not be read; an error is then added.
func (r *certificateResource) revocationDone(ctx context.Context, eid int64, diags *diag.Diagnostics) (done, ok bool) {
	d, err := r.client.GetEnrollmentDetails(ctx, eid)
	if client.IsNotFound(err) {
		tflog.Info(ctx, "Enrollment no longer exists in CertSecure; nothing to revoke", map[string]any{"enrollment_id": eid})
		return true, true
	}
	if err != nil {
		summary, detail := describeAPIError(err)
		diags.AddError("Error reading certificate before revocation: "+summary,
			detail+fmt.Sprintf("\n\nEnrollment ID (eid) %d was not revoked and is kept in state; run destroy again.", eid))
		return false, false
	}
	switch strings.ToLower(d.Status) {
	case "active":
		return false, true
	case "revoked", "expired":
		tflog.Info(ctx, "Certificate needs no revocation", map[string]any{"enrollment_id": eid, "status": d.Status})
		return true, true
	}
	diags.AddWarning("Certificate was NOT revoked",
		fmt.Sprintf("Enrollment ID (eid) %d has status %q in CertSecure, and only active certificates can be revoked. It is "+
			"removed from Terraform state. If it is a request awaiting approval, deny it in CertSecure.", eid, d.Status))
	return true, true
}

// waitForRevocation follows the revocation task of eid until CertSecure
// reports the certificate as revoked, the task fails, or ctx expires.
func (r *certificateResource) waitForRevocation(ctx context.Context, eid int64, taskID string) *createError {
	kept := fmt.Sprintf("\n\nRevocation task %s, enrollment ID (eid) %d. The certificate is kept in state.", taskID, eid)
	var lastState string
	interval := pollInitialInterval
	for {
		task, err := r.client.GetTask(ctx, taskID)
		switch {
		case client.IsUnauthorized(err) || client.IsForbidden(err):
			summary, detail := describeAPIError(err)
			return &createError{summary: "Error checking certificate revocation: " + summary, detail: detail + kept}
		case err != nil:
			tflog.Debug(ctx, "Task lookup failed, will retry", map[string]any{"task_id": taskID, "error": err.Error()})
		case task.IsFailed():
			return &createError{
				summary: "Certificate revocation failed in CertSecure",
				detail: fmt.Sprintf("CertSecure reported %q: %s%s It is still active; running destroy again submits a "+
					"new revocation.", task.Status, task.Details, kept),
			}
		default:
			lastState = fmt.Sprintf("task %s: %s (%s)", task.StatusInfo, task.Status, task.Details)
		}

		// The task turns OK first; the enrollment record is marked revoked
		// right after.
		if d, err := r.client.GetEnrollmentDetails(ctx, eid); err == nil {
			if strings.EqualFold(d.Status, "revoked") {
				return nil
			}
			lastState += fmt.Sprintf(", enrollment status %q", d.Status)
		}

		select {
		case <-ctx.Done():
			detail := "The revocation did not complete before the timeout expired."
			if lastState != "" {
				detail += " Last known state: " + strings.TrimPrefix(lastState, ", ") + "."
			}
			return &createError{
				summary: "Timed out waiting for certificate revocation",
				detail: detail + kept + " Running destroy again checks the certificate first and does not revoke it twice " +
					"once this revocation has completed; increase timeouts.delete if the CA is slow.",
			}
		case <-time.After(interval):
		}
		interval = min(interval*2, pollMaxInterval)
	}
}

// describeRevokeError maps a revoke_cert submission error to a diagnostic.
func describeRevokeError(err error, eid int64) (summary, detail string) {
	if client.IsForbidden(err) {
		return "Not allowed to revoke this certificate",
			fmt.Sprintf("The CertSecure user of the API token must be the owner of enrollment ID (eid) %d, a department PKI "+
				"admin for its CA, or a global admin, and needs the View Enrollment Database permission. The certificate was "+
				"not revoked and is kept in state.\n\n%s", eid, err)
	}
	summary, detail = describeAPIError(err)
	detail += fmt.Sprintf("\n\nEnrollment ID (eid) %d is kept in state.", eid)
	if !client.IsBadRequest(err) && !client.IsUnauthorized(err) && !client.IsNotFound(err) {
		detail += " The revocation may still have been queued by CertSecure. Running destroy again checks the certificate " +
			"first and does not revoke it twice once that revocation has completed."
	}
	return summary, detail
}

func valueOr(v types.String, fallback string) string {
	if v.IsNull() || v.IsUnknown() || v.ValueString() == "" {
		return fallback
	}
	return v.ValueString()
}

func (r *certificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	eid, err := strconv.ParseInt(strings.TrimSpace(req.ID), 10, 64)
	if err != nil || eid <= 0 {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Expected a CertSecure enrollment ID (a positive integer), got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), strconv.FormatInt(eid, 10))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("enrollment_id"), eid)...)
}
