from __future__ import annotations

from broker.models import CredentialTemplate, FieldDefinition, TemplateType

# ---------------------------------------------------------------------------
# Built-in FORM templates
# ---------------------------------------------------------------------------

BUILTIN_TEMPLATES: dict[str, CredentialTemplate] = {
    # Generic form templates
    "api_key": CredentialTemplate(
        template_id="api_key",
        display_name="API Key",
        fields=[
            FieldDefinition(name="api_key", label="API Key", type="password"),
        ],
    ),
    "basic_auth": CredentialTemplate(
        template_id="basic_auth",
        display_name="Login Credentials",
        fields=[
            FieldDefinition(name="username", label="Username", type="text"),
            FieldDefinition(name="password", label="Password", type="password"),
        ],
    ),
    "aws": CredentialTemplate(
        template_id="aws",
        display_name="AWS Credentials",
        fields=[
            FieldDefinition(name="access_key_id", label="Access Key ID", type="text"),
            FieldDefinition(name="secret_access_key", label="Secret Access Key", type="password"),
            FieldDefinition(name="region", label="Region", type="text", required=False),
        ],
    ),
    # Convenience aliases — same template type, different label
    "openai": CredentialTemplate(
        template_id="openai",
        display_name="OpenAI",
        fields=[
            FieldDefinition(name="api_key", label="OpenAI API Key", type="password"),
        ],
    ),
    "anthropic": CredentialTemplate(
        template_id="anthropic",
        display_name="Anthropic",
        fields=[
            FieldDefinition(name="api_key", label="Anthropic API Key", type="password"),
        ],
    ),
}

# ---------------------------------------------------------------------------
# Built-in OAUTH templates (require provider config in config.yaml)
# ---------------------------------------------------------------------------

BUILTIN_OAUTH_TEMPLATES: dict[str, CredentialTemplate] = {
    "google_mail": CredentialTemplate(
        template_id="google_mail",
        display_name="Google Mail",
        template_type=TemplateType.OAUTH,
        oauth_provider="google",
        oauth_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    ),
    "google_drive": CredentialTemplate(
        template_id="google_drive",
        display_name="Google Drive",
        template_type=TemplateType.OAUTH,
        oauth_provider="google",
        oauth_scopes=["https://www.googleapis.com/auth/drive.readonly"],
    ),
    "microsoft_mail": CredentialTemplate(
        template_id="microsoft_mail",
        display_name="Microsoft Outlook",
        template_type=TemplateType.OAUTH,
        oauth_provider="microsoft",
        oauth_scopes=["https://graph.microsoft.com/Mail.Read"],
    ),
    "github": CredentialTemplate(
        template_id="github",
        display_name="GitHub",
        template_type=TemplateType.OAUTH,
        oauth_provider="github",
        oauth_scopes=["read:user", "repo"],
    ),
    "slack": CredentialTemplate(
        template_id="slack",
        display_name="Slack",
        template_type=TemplateType.OAUTH,
        oauth_provider="slack",
        oauth_scopes=["chat:write", "channels:read"],
    ),
}

# Merge all built-in templates
ALL_BUILTIN_TEMPLATES: dict[str, CredentialTemplate] = {
    **BUILTIN_TEMPLATES,
    **BUILTIN_OAUTH_TEMPLATES,
}


def resolve_template(
    template_id: str | None,
    display_name: str | None = None,
    fields: list[dict] | None = None,
    oauth_provider: str | None = None,
    oauth_scopes: list[str] | None = None,
) -> CredentialTemplate:
    """Resolve a template from a built-in ID, custom fields, or OAuth config."""
    # 1. Built-in template lookup
    if template_id and template_id not in ("custom", "oauth") and template_id in ALL_BUILTIN_TEMPLATES:
        tpl = ALL_BUILTIN_TEMPLATES[template_id]
        # Allow display_name override
        if display_name:
            return CredentialTemplate(
                template_id=tpl.template_id,
                display_name=display_name,
                template_type=tpl.template_type,
                fields=tpl.fields,
                oauth_provider=tpl.oauth_provider,
                oauth_scopes=tpl.oauth_scopes,
                builtin=tpl.builtin,
            )
        return tpl

    # 2. Custom OAuth template (provider specified inline)
    if template_id == "oauth" and oauth_provider:
        return CredentialTemplate(
            template_id="oauth",
            display_name=display_name or f"OAuth ({oauth_provider})",
            template_type=TemplateType.OAUTH,
            oauth_provider=oauth_provider,
            oauth_scopes=oauth_scopes or [],
            builtin=False,
        )

    # 3. Custom form template (fields specified inline)
    if fields:
        return CredentialTemplate(
            template_id=template_id or "custom",
            display_name=display_name or "Custom Credentials",
            template_type=TemplateType.FORM,
            fields=[FieldDefinition(**f) for f in fields],
            builtin=False,
        )

    raise ValueError(
        f"Unknown template '{template_id}' and no custom fields or OAuth provider provided"
    )
