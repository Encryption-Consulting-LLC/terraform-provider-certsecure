// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Encryption-Consulting-LLC/terraform-provider-certsecure/internal/client"
)

var (
	_ datasource.DataSourceWithConfigure        = &certificateDataSource{}
	_ datasource.DataSourceWithConfigValidators = &certificateDataSource{}
)

// serialPattern accepts a hexadecimal serial number in upper or lower case,
// optionally prefixed with 0x and grouped with colons, hyphens or spaces.
var serialPattern = regexp.MustCompile(`^(0[xX])?[0-9a-fA-F]+([:\- ][0-9a-fA-F]+)*$`)

// NewCertificateDataSource returns the certsecure_certificate data source.
func NewCertificateDataSource() datasource.DataSource {
	return &certificateDataSource{}
}

type certificateDataSource struct {
	client *client.Client
}

type certificateDataSourceModel struct {
	EnrollmentID   types.Int64  `tfsdk:"enrollment_id"`
	ID             types.String `tfsdk:"id"`
	Status         types.String `tfsdk:"status"`
	CAName         types.String `tfsdk:"ca_name"`
	Template       types.String `tfsdk:"template"`
	CommonName     types.String `tfsdk:"common_name"`
	DNSNames       []string     `tfsdk:"dns_names"`
	Tags           []string     `tfsdk:"tags"`
	CertificatePEM types.String `tfsdk:"certificate_pem"`
	ChainPEM       types.String `tfsdk:"chain_pem"`
	SerialNumber   types.String `tfsdk:"serial_number"`
	NotBefore      types.String `tfsdk:"not_before"`
	NotAfter       types.String `tfsdk:"not_after"`
}

func (d *certificateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (d *certificateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	str := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{MarkdownDescription: desc, Computed: true}
	}
	strList := func(desc string) schema.ListAttribute {
		return schema.ListAttribute{MarkdownDescription: desc, ElementType: types.StringType, Computed: true}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads an existing certificate from CertSecure, for example one requested in the " +
			"CertSecure portal or by another Terraform configuration. Look it up either by enrollment ID or by serial " +
			"number and CA. The data source never issues, renews or revokes a certificate.",
		Attributes: map[string]schema.Attribute{
			"enrollment_id": schema.Int64Attribute{
				MarkdownDescription: "CertSecure enrollment ID (`eid`) of the certificate, for example " +
					"`certsecure_certificate.example.enrollment_id` from another configuration. Set either " +
					"`enrollment_id`, or `serial_number` and `ca_name`. Filled in when you look up by serial number.",
				Optional:   true,
				Computed:   true,
				Validators: []validator.Int64{int64validator.AtLeast(1)},
			},
			"serial_number": schema.StringAttribute{
				MarkdownDescription: "Certificate serial number in hexadecimal. To look up by serial number, set it " +
					"together with `ca_name`, in upper or lower case, with or without colons (for example " +
					"`3400033ba9...` or `34:00:03:3B:A9:...`); it keeps the value you set. Otherwise it is filled in as " +
					"lowercase hexadecimal.",
				Optional:   true,
				Computed:   true,
				Validators: []validator.String{stringvalidator.RegexMatches(serialPattern, "must be a hexadecimal serial number")},
			},
			"ca_name": schema.StringAttribute{
				MarkdownDescription: "Name of the CA that issued the certificate. Required with `serial_number`; " +
					"otherwise filled in.",
				Optional:   true,
				Computed:   true,
				Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"id":              str("The enrollment ID, as a string."),
			"status":          str("Enrollment status reported by CertSecure, e.g. `active`, `expired` or `revoked`."),
			"template":        str("Certificate template the certificate was issued with."),
			"common_name":     str("Subject common name of the certificate."),
			"dns_names":       strList("DNS names in the certificate's subject alternative names."),
			"tags":            strList("Tags recorded on the certificate in CertSecure."),
			"certificate_pem": str("The certificate, PEM encoded."),
			"chain_pem": str("The issuing CA chain as concatenated PEM certificates, issuer first. Does not include " +
				"the certificate itself."),
			"not_before": str("Start of the certificate validity period (RFC 3339)."),
			"not_after":  str("End of the certificate validity period (RFC 3339)."),
		},
	}
}

func (d *certificateDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(path.MatchRoot("enrollment_id"), path.MatchRoot("serial_number")),
		datasourcevalidator.RequiredTogether(path.MatchRoot("serial_number"), path.MatchRoot("ca_name")),
		datasourcevalidator.Conflicting(path.MatchRoot("enrollment_id"), path.MatchRoot("ca_name")),
	}
}

func (d *certificateDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *providerData, got %T", req.ProviderData))
		return
	}
	d.client = data.client
}

func (d *certificateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg certificateDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	bySerial := !cfg.SerialNumber.IsNull()

	var (
		eid     int64
		details *client.EnrollmentDetails
		serial  *big.Int
		err     error
	)
	if bySerial {
		ca, hex := cfg.CAName.ValueString(), normalizeSerial(cfg.SerialNumber.ValueString())
		serial, _ = new(big.Int).SetString(hex, 16)
		notFound := fmt.Sprintf("CertSecure has no certificate with serial number %s on CA %q, or the token cannot view it.",
			cfg.SerialNumber.ValueString(), ca)

		details, err = d.client.GetEnrollmentDetailsBySerial(ctx, hex, ca)
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError("Certificate not found", notFound)
			return
		}
		if err != nil {
			summary, detail := describeAPIError(err)
			resp.Diagnostics.AddError("Error looking up certificate by serial number: "+summary, detail)
			return
		}
		// CertSecure matches the serial number on any CA; only the configured CA counts.
		if !strings.EqualFold(details.CertificateAuthority, ca) {
			resp.Diagnostics.AddError("Certificate not found", notFound)
			return
		}
		if details.EnrollmentID == 0 {
			resp.Diagnostics.AddError("Certificate not enrolled through CertSecure",
				fmt.Sprintf("CertSecure knows the certificate with serial number %s on CA %q only from the CA "+
					"inventory. It was not requested through CertSecure enrollment, so the data source cannot read it.",
					cfg.SerialNumber.ValueString(), ca))
			return
		}
		eid = details.EnrollmentID
	} else {
		eid = cfg.EnrollmentID.ValueInt64()
		details, err = d.client.GetEnrollmentDetails(ctx, eid)
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError("Certificate not found",
				fmt.Sprintf("CertSecure has no enrollment with ID %d, or the token cannot view it.", eid))
			return
		}
		if err != nil {
			summary, detail := describeAPIError(err)
			resp.Diagnostics.AddError("Error reading certificate enrollment: "+summary, detail)
			return
		}
	}
	if !details.CertAvailable {
		resp.Diagnostics.AddError("Certificate not available",
			fmt.Sprintf("Enrollment %d has no certificate to read (status %q). A request that is pending or awaits "+
				"approval has no certificate until it is issued.", eid, details.Status))
		return
	}

	leaf, err := d.client.DownloadCert(ctx, eid)
	if err != nil {
		summary, detail := describeAPIError(err)
		resp.Diagnostics.AddError("Error downloading certificate: "+summary, detail)
		return
	}
	if serial != nil && leaf.SerialNumber.Cmp(serial) != 0 {
		resp.Diagnostics.AddError("Certificate serial number mismatch",
			fmt.Sprintf("CertSecure returned enrollment %d for serial number %s, but its certificate has serial number %s.",
				eid, cfg.SerialNumber.ValueString(), client.SerialHex(leaf)))
		return
	}
	bundle, err := d.client.DownloadChain(ctx, eid)
	if err != nil {
		summary, detail := describeAPIError(err)
		resp.Diagnostics.AddError("Error downloading certificate chain: "+summary, detail)
		return
	}
	chain := client.BuildChain(leaf, bundle)

	state := certificateDataSourceModel{
		EnrollmentID:   types.Int64Value(eid),
		ID:             types.StringValue(strconv.FormatInt(eid, 10)),
		Status:         types.StringValue(details.Status),
		CAName:         types.StringValue(details.CertificateAuthority),
		Template:       types.StringValue(details.Template),
		CommonName:     types.StringValue(leaf.Subject.CommonName),
		DNSNames:       append([]string{}, leaf.DNSNames...),
		Tags:           append([]string{}, details.Tags...),
		CertificatePEM: types.StringValue(client.EncodePEM(leaf)),
		ChainPEM:       types.StringValue(""),
		SerialNumber:   types.StringValue(client.SerialHex(leaf)),
		NotBefore:      types.StringValue(leaf.NotBefore.UTC().Format(time.RFC3339)),
		NotAfter:       types.StringValue(leaf.NotAfter.UTC().Format(time.RFC3339)),
	}
	if len(chain) > 0 {
		state.ChainPEM = types.StringValue(client.EncodePEM(chain...))
	}
	// Terraform requires configured arguments to come back unchanged.
	if bySerial {
		state.SerialNumber, state.CAName = cfg.SerialNumber, cfg.CAName
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// normalizeSerial returns a serial number as lowercase hexadecimal without a
// 0x prefix, separators or leading zeros.
func normalizeSerial(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 1 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	s = strings.ToLower(strings.NewReplacer(":", "", "-", "", " ", "").Replace(s))
	if t := strings.TrimLeft(s, "0"); t != "" {
		return t
	}
	return "0"
}
