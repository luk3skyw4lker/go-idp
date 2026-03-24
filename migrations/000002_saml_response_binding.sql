-- +goose Up
ALTER TABLE saml_sp_registry
  ADD COLUMN IF NOT EXISTS response_binding text NOT NULL DEFAULT 'HTTP-POST';

ALTER TABLE saml_sp_registry
  DROP CONSTRAINT IF EXISTS saml_sp_registry_response_binding_check;

ALTER TABLE saml_sp_registry
  ADD CONSTRAINT saml_sp_registry_response_binding_check
  CHECK (response_binding IN ('HTTP-POST', 'HTTP-Redirect'));

-- +goose Down
ALTER TABLE saml_sp_registry
  DROP CONSTRAINT IF EXISTS saml_sp_registry_response_binding_check;

ALTER TABLE saml_sp_registry
  DROP COLUMN IF EXISTS response_binding;
