// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Encryption-Consulting-LLC/terraform-provider-certsecure/internal/client"
)

const (
	envURL      = "CERTSECURE_URL"
	envToken    = "CERTSECURE_TOKEN"
	envCABundle = "CERTSECURE_CA_BUNDLE"
)

var _ provider.Provider = &certSecureProvider{}

type certSecureProvider struct {
	version string
}

type providerModel struct {
	URL                types.String `tfsdk:"url"`
	Token              types.String `tfsdk:"token"`
	CABundlePEM        types.String `tfsdk:"ca_bundle_pem"`
	InsecureSkipVerify types.Bool   `tfsdk:"insecure_skip_verify"`
	RequestTimeout     types.String `tfsdk:"request_timeout"`
}

// New returns a constructor for the provider at the given version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &certSecureProvider{version: version}
	}
}

func (p *certSecureProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "certsecure"
	resp.Version = p.version
}

func (p *certSecureProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The CertSecure provider issues certificates through " +
			"[CertSecure Manager](https://www.encryptionconsulting.com/) from CAs connected to it, " +
			"such as Microsoft CA (AD CS). The provider only talks to the CertSecure REST API.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				MarkdownDescription: "Base URL of the CertSecure API, e.g. `https://certsecure.example.com`. " +
					"Can also be set with the `" + envURL + "` environment variable.",
				Optional: true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "CertSecure API token, without the `Bearer ` prefix. Tokens are created in " +
					"CertSecure (API Token Management); the provider never creates them. " +
					"Can also be set with the `" + envToken + "` environment variable.",
				Optional:  true,
				Sensitive: true,
			},
			"ca_bundle_pem": schema.StringAttribute{
				MarkdownDescription: "PEM-encoded CA certificate(s) to trust for TLS connections to CertSecure, " +
					"in addition to the system trust store. Can also be set with the `" + envCABundle + "` environment variable.",
				Optional: true,
			},
			"insecure_skip_verify": schema.BoolAttribute{
				MarkdownDescription: "Skip TLS certificate verification of the CertSecure API. **For lab use only.** Defaults to `false`.",
				Optional:            true,
			},
			"request_timeout": schema.StringAttribute{
				MarkdownDescription: "Timeout for each HTTP request to CertSecure, as a Go duration string. Defaults to `\"60s\"`.",
				Optional:            true,
				Validators:          []validator.String{durationValidator{}},
			},
		},
	}
}

// providerData is handed to resources and data sources.
type providerData struct {
	client *client.Client
}

func (p *certSecureProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for attr, v := range map[string]types.String{"url": cfg.URL, "token": cfg.Token, "ca_bundle_pem": cfg.CABundlePEM, "request_timeout": cfg.RequestTimeout} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(attr), "Unknown CertSecure provider configuration",
				fmt.Sprintf("The provider cannot be configured because %q is not known until apply. "+
					"Set it to a static value or use the corresponding environment variable.", attr))
		}
	}
	if cfg.InsecureSkipVerify.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("insecure_skip_verify"), "Unknown CertSecure provider configuration",
			"insecure_skip_verify must be known when the provider is configured.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Attributes set in configuration override environment variables.
	url := stringOrEnv(cfg.URL, envURL)
	token := stringOrEnv(cfg.Token, envToken)
	caBundle := stringOrEnv(cfg.CABundlePEM, envCABundle)

	if url == "" {
		resp.Diagnostics.AddAttributeError(path.Root("url"), "Missing CertSecure URL",
			"Set the provider's url attribute or the "+envURL+" environment variable.")
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("token"), "Missing CertSecure token",
			"Set the provider's token attribute or the "+envToken+" environment variable.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	timeout := client.DefaultTimeout
	if s := cfg.RequestTimeout.ValueString(); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			resp.Diagnostics.AddAttributeError(path.Root("request_timeout"), "Invalid request_timeout",
				fmt.Sprintf("%q is not a positive duration such as \"60s\".", s))
			return
		}
		timeout = d
	}

	insecure := cfg.InsecureSkipVerify.ValueBool()
	if insecure {
		tflog.Warn(ctx, "insecure_skip_verify is enabled: TLS certificates of the CertSecure API are not verified")
	}

	c, err := client.New(client.Config{
		URL:                url,
		Token:              token,
		CABundlePEM:        caBundle,
		InsecureSkipVerify: insecure,
		Timeout:            timeout,
		UserAgent:          fmt.Sprintf("terraform-provider-certsecure/%s terraform/%s", p.version, req.TerraformVersion),
		Logger: func(ctx context.Context, msg string, fields map[string]any) {
			tflog.Debug(ctx, msg, fields)
		},
	})
	if err != nil {
		resp.Diagnostics.AddError("Invalid CertSecure provider configuration", err.Error())
		return
	}

	// Fail early with a clear message when the token is not usable.
	if err := c.CheckToken(ctx); err != nil {
		summary, detail := describeAPIError(err)
		resp.Diagnostics.AddError("Unable to authenticate to CertSecure: "+summary, detail)
		return
	}

	if v, err := c.Version(ctx); err == nil {
		tflog.Info(ctx, "Connected to CertSecure", map[string]any{"backend_version": v.Backend, "frontend_version": v.Frontend, "mode": v.Mode})
	} else {
		tflog.Debug(ctx, "Could not read CertSecure version", map[string]any{"error": err.Error()})
	}

	data := &providerData{client: c}
	resp.ResourceData = data
	resp.DataSourceData = data
}

func (p *certSecureProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertificateResource,
	}
}

func (p *certSecureProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewCAsDataSource,
		NewTemplatesDataSource,
	}
}

func stringOrEnv(v types.String, env string) string {
	if !v.IsNull() && v.ValueString() != "" {
		return strings.TrimSpace(v.ValueString())
	}
	return strings.TrimSpace(os.Getenv(env))
}

// durationValidator checks that a string parses as a positive Go duration.
type durationValidator struct{}

func (durationValidator) Description(context.Context) string {
	return "value must be a positive duration such as \"60s\" or \"2m\""
}

func (v durationValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v durationValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	d, err := time.ParseDuration(req.ConfigValue.ValueString())
	if err != nil || d <= 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid duration", v.Description(ctx))
	}
}
