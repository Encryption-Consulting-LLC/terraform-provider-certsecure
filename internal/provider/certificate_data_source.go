// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Encryption-Consulting-LLC/terraform-provider-certsecure/internal/client"
)

var _ datasource.DataSourceWithConfigure = &certificateDataSource{}

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
		MarkdownDescription: "Reads an existing certificate from CertSecure by its enrollment ID, for example one " +
			"requested in the CertSecure portal or by another Terraform configuration. The data source never issues, " +
			"renews or revokes a certificate.",
		Attributes: map[string]schema.Attribute{
			"enrollment_id": schema.Int64Attribute{
				MarkdownDescription: "CertSecure enrollment ID (`eid`) of the certificate, for example " +
					"`certsecure_certificate.example.enrollment_id` from another configuration.",
				Required:   true,
				Validators: []validator.Int64{int64validator.AtLeast(1)},
			},
			"id":              str("The enrollment ID, as a string."),
			"status":          str("Enrollment status reported by CertSecure, e.g. `active`, `expired` or `revoked`."),
			"ca_name":         str("Name of the CA that issued the certificate."),
			"template":        str("Certificate template the certificate was issued with."),
			"common_name":     str("Subject common name of the certificate."),
			"dns_names":       strList("DNS names in the certificate's subject alternative names."),
			"tags":            strList("Tags recorded on the certificate in CertSecure."),
			"certificate_pem": str("The certificate, PEM encoded."),
			"chain_pem": str("The issuing CA chain as concatenated PEM certificates, issuer first. Does not include " +
				"the certificate itself."),
			"serial_number": str("Certificate serial number as lowercase hexadecimal."),
			"not_before":    str("Start of the certificate validity period (RFC 3339)."),
			"not_after":     str("End of the certificate validity period (RFC 3339)."),
		},
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
	eid := cfg.EnrollmentID.ValueInt64()

	details, err := d.client.GetEnrollmentDetails(ctx, eid)
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
	bundle, err := d.client.DownloadChain(ctx, eid)
	if err != nil {
		summary, detail := describeAPIError(err)
		resp.Diagnostics.AddError("Error downloading certificate chain: "+summary, detail)
		return
	}
	chain := client.BuildChain(leaf, bundle)

	state := certificateDataSourceModel{
		EnrollmentID:   cfg.EnrollmentID,
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
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
