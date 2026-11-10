// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Encryption-Consulting-LLC/terraform-provider-certsecure/internal/client"
)

var _ datasource.DataSourceWithConfigure = &templatesDataSource{}

// NewTemplatesDataSource returns the certsecure_templates data source.
func NewTemplatesDataSource() datasource.DataSource {
	return &templatesDataSource{}
}

type templatesDataSource struct {
	client *client.Client
}

type templatesDataSourceModel struct {
	CAName    types.String    `tfsdk:"ca_name"`
	Names     []string        `tfsdk:"names"`
	Templates []templateModel `tfsdk:"templates"`
}

type templateModel struct {
	FriendlyName      string   `tfsdk:"friendly_name"`
	Description       string   `tfsdk:"description"`
	OID               string   `tfsdk:"oid"`
	MinKeySize        string   `tfsdk:"min_key_size"`
	ValidityPeriod    string   `tfsdk:"validity_period"`
	RenewalPeriod     string   `tfsdk:"renewal_period"`
	KeyUsages         string   `tfsdk:"key_usages"`
	EnhancedKeyUsages []string `tfsdk:"enhanced_key_usages"`
	EnrollmentFlags   []string `tfsdk:"enrollment_flags"`
}

func (d *templatesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_templates"
}

func (d *templatesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	str := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{MarkdownDescription: desc, Computed: true}
	}
	strList := func(desc string) schema.ListAttribute {
		return schema.ListAttribute{MarkdownDescription: desc, ElementType: types.StringType, Computed: true}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the certificate templates available on a CA in CertSecure.\n\n" +
			"Use a value from `names` as `template` in `certsecure_certificate`. For Microsoft CA, `names` holds template names " +
			"(e.g. `WebServer`), while `templates[*].friendly_name` holds display names (e.g. `Web Server`), which enrollment does not accept.",
		Attributes: map[string]schema.Attribute{
			"ca_name": schema.StringAttribute{
				MarkdownDescription: "CA name, as listed by the `certsecure_cas` data source.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"names": strList("Template names accepted by `certsecure_certificate.template`, sorted."),
			"templates": schema.ListNestedAttribute{
				MarkdownDescription: "Template details. Empty when CertSecure has no template details for the CA " +
					"(for example when its connector is offline).",
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"friendly_name":       str("Template display name."),
						"description":         str("Template description (for Microsoft CA, the subject type such as `Computer` or `User`)."),
						"oid":                 str("Template OID."),
						"min_key_size":        str("Minimum key size."),
						"validity_period":     str("Validity period, e.g. `2 Years`."),
						"renewal_period":      str("Renewal period, e.g. `6 Weeks`."),
						"key_usages":          str("Key usages."),
						"enhanced_key_usages": strList("Extended key usages."),
						"enrollment_flags":    strList("Template enrollment flags."),
					},
				},
			},
		},
	}
}

func (d *templatesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *templatesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg templatesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ca := cfg.CAName.ValueString()

	names, err := d.client.ListTemplateNames(ctx, ca)
	if err != nil {
		summary, detail := describeAPIError(err)
		resp.Diagnostics.AddError("Error listing templates for CA "+ca+": "+summary, detail)
		return
	}
	details, err := d.client.GetCATemplates(ctx, ca)
	if err != nil {
		summary, detail := describeAPIError(err)
		resp.Diagnostics.AddError("Error reading template details for CA "+ca+": "+summary, detail)
		return
	}

	state := templatesDataSourceModel{CAName: cfg.CAName, Names: append([]string{}, names...), Templates: []templateModel{}}
	sortStrings(state.Names)
	for _, t := range details {
		state.Templates = append(state.Templates, templateModel{
			FriendlyName:      t.FriendlyName,
			Description:       t.Description,
			OID:               t.TemplateOID,
			MinKeySize:        t.MinKeySize,
			ValidityPeriod:    t.ValidityPeriod,
			RenewalPeriod:     t.RenewalPeriod,
			KeyUsages:         t.KeyUsages,
			EnhancedKeyUsages: nonNilStrings(t.EnhancedKeyUsages),
			EnrollmentFlags:   nonNilStrings(t.EnrollmentFlags),
		})
	}
	sort.SliceStable(state.Templates, func(i, j int) bool { return state.Templates[i].FriendlyName < state.Templates[j].FriendlyName })
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func sortStrings(s []string) { sort.Strings(s) }

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
