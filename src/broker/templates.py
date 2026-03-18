from __future__ import annotations

from broker.models import CredentialTemplate, FieldDefinition

BUILTIN_TEMPLATES: dict[str, CredentialTemplate] = {
    "api_key": CredentialTemplate(
        template_id="api_key",
        display_name="API Key",
        fields=[
            FieldDefinition(name="api_key", label="API Key", type="password"),
        ],
    ),
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
    "aws": CredentialTemplate(
        template_id="aws",
        display_name="AWS Credentials",
        fields=[
            FieldDefinition(name="access_key_id", label="Access Key ID", type="text"),
            FieldDefinition(name="secret_access_key", label="Secret Access Key", type="password"),
            FieldDefinition(name="region", label="Region", type="text", required=False),
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
}


def resolve_template(
    template_id: str | None,
    display_name: str | None = None,
    fields: list[dict] | None = None,
) -> CredentialTemplate:
    """Resolve a template from a built-in ID or custom field definitions."""
    if template_id and template_id != "custom" and template_id in BUILTIN_TEMPLATES:
        return BUILTIN_TEMPLATES[template_id]

    if fields:
        return CredentialTemplate(
            template_id=template_id or "custom",
            display_name=display_name or "Custom Credentials",
            fields=[FieldDefinition(**f) for f in fields],
            builtin=False,
        )

    raise ValueError(
        f"Unknown template '{template_id}' and no custom fields provided"
    )
