// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Encryption-Consulting-LLC/terraform-provider-certsecure/internal/client"
)

var _ datasource.DataSourceWithConfigure = &casDataSource{}

// NewCAsDataSource returns the certsecure_cas data source.
func NewCAsDataSource() datasource.DataSource {
	return &casDataSource{}
}

type casDataSource struct {
	client *client.Client
}

type casDataSourceModel struct {
	Type  types.String `tfsdk:"type"`
	Names []string     `tfsdk:"names"`
	CAs   []caModel    `tfsdk:"cas"`
}

type caModel struct {
	Name       string   `tfsdk:"name"`
	Type       string   `tfsdk:"type"`
	Connectors []string `tfsdk:"connectors"`
}

func (d *casDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cas"
}

func (d *casDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the CAs the provider's token may enroll from in CertSecure. " +
			"Use the names as `ca_name` in `certsecure_certificate`.",
		Attributes: map[string]schema.Attribute{
			"type": schema.StringAttribute{
				MarkdownDescription: "Only return CAs of this type, e.g. `MSCA` for Microsoft CA. Case-insensitive.",
				Optional:            true,
			},
			"names": schema.ListAttribute{
				MarkdownDescription: "CA names, sorted.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"cas": schema.ListNestedAttribute{
				MarkdownDescription: "CAs with their details, sorted by type and name.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							MarkdownDescription: "CA name.",
							Computed:            true,
						},
						"type": schema.StringAttribute{
							MarkdownDescription: "CA type as reported by CertSecure, e.g. `MSCA`.",
							Computed:            true,
						},
						"connectors": schema.ListAttribute{
							MarkdownDescription: "CertSecure connectors that serve this CA.",
							ElementType:         types.StringType,
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

func (d *casDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *casDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg casDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cas, err := d.client.ListAvailableCAs(ctx)
	if err != nil {
		summary, detail := describeAPIError(err)
		if client.IsUnauthorized(err) {
			// The token passed the check when the provider was configured, so it is
			// valid and the 401 is specific to this endpoint.
			detail = "CertSecure accepted the token when the provider was configured, but refused it for the CA list. " +
				"Use an API token created in CertSecure (API Token Management).\n\n" + detail
		}
		resp.Diagnostics.AddError("Error listing CertSecure CAs: "+summary, detail)
		return
	}

	filter := strings.TrimSpace(cfg.Type.ValueString())
	state := casDataSourceModel{Type: cfg.Type, Names: []string{}, CAs: []caModel{}}
	seen := map[string]bool{}
	for _, ca := range cas {
		if filter != "" && !strings.EqualFold(ca.Type, filter) {
			continue
		}
		state.CAs = append(state.CAs, caModel{Name: ca.Name, Type: ca.Type, Connectors: ca.Connectors})
		if !seen[ca.Name] {
			seen[ca.Name] = true
			state.Names = append(state.Names, ca.Name)
		}
	}
	sortStrings(state.Names)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
