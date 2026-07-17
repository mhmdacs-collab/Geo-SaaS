-- إنشاء جدول فواتير المشتريات من الداش بورد (QR)
CREATE TABLE dashboard_purchase_invoice (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  device_id UUID NOT NULL REFERENCES devices(id),
  seller_name TEXT NOT NULL,
  seller_tax_number TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL,
  total_amount NUMERIC(12,2) NOT NULL,
  vat_amount NUMERIC(12,2) NOT NULL,
  qr_payload TEXT NOT NULL,
  qr_payload_hash TEXT NOT NULL,
  responsibility_confirmed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- فهارس للأداء
CREATE INDEX idx_dpi_tenant_device ON dashboard_purchase_invoice(tenant_id, device_id);
CREATE INDEX idx_dpi_hash ON dashboard_purchase_invoice(qr_payload_hash);
CREATE INDEX idx_dpi_duplicate_check ON dashboard_purchase_invoice(tenant_id, device_id, seller_tax_number, issued_at, total_amount, vat_amount);
