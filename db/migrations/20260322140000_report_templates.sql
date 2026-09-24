-- Migration: report_templates
-- Allows users to define reusable report templates with custom sections and branding

CREATE TABLE IF NOT EXISTS report_templates (
  id          SERIAL PRIMARY KEY,
  name        VARCHAR(255)  NOT NULL,
  description TEXT,
  config      JSONB         NOT NULL DEFAULT '{}',
  is_default  BOOLEAN       NOT NULL DEFAULT false,
  created_by  UUID          REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- No predefined templates — users create their own via the interface.
