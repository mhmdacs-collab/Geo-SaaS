"""
TABLE_MAP — whitelist of syncable tables and their Aronium->Postgres column maps.

Anything not listed here is rejected. This is the security boundary that
prevents a compromised agent from writing arbitrary SQL identifiers.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import HTTPException


def _t(
    pg_table: str,
    columns: Dict[str, str],
    conflict: List[str],
    pk_col: str = "aronium_id",
    pk_composite_cols: List[str] | None = None,
) -> Dict[str, Any]:
    """columns: { aronium_name: pg_name }. 'aronium_id' (pk) is required unless composite."""
    if pk_composite_cols:
        pk_text_expr = " || '|' || ".join(f'{c}::text' for c in pk_composite_cols)
        return {
            "pg_table": pg_table,
            "columns": columns,
            "conflict": conflict,
            "pk_composite_cols": pk_composite_cols,
            "pk_text_expr": pk_text_expr,
        }
    return {
        "pg_table": pg_table,
        "columns": columns,
        "conflict": conflict,
        "pk_col": pk_col,
        "pk_text_expr": f"{pk_col}::text",
    }


TABLE_MAP: Dict[str, Dict[str, Any]] = {
    # ----- reference -----
    "Company": _t(
        "ar_company",
        {"Id":"aronium_id","Name":"name","Address":"address","PostalCode":"postal_code",
         "City":"city","CountryId":"country_id","TaxNumber":"tax_number","Email":"email",
         "PhoneNumber":"phone_number","BankAccountNumber":"bank_account_number",
         "BankDetails":"bank_details","StreetName":"street_name",
         "AdditionalStreetName":"additional_street_name","BuildingNumber":"building_number",
         "PlotIdentification":"plot_identification","CitySubdivisionName":"city_subdivision_name",
         "CountrySubentity":"country_subentity"},
        conflict=["tenant_id","aronium_id"],
    ),
    "Country": _t("ar_countries",
        {"Id":"aronium_id","Name":"name","Code":"code"},
        conflict=["tenant_id","aronium_id"]),
    "Currency": _t("ar_currencies",
        {"Id":"aronium_id","Name":"name","Code":"code"},
        conflict=["tenant_id","aronium_id"]),
    "Warehouse": _t("ar_warehouses",
        {"Id":"aronium_id","Name":"name"},
        conflict=["tenant_id","aronium_id"]),
    "ProductGroup": _t("ar_product_groups",
        {"Id":"aronium_id","Name":"name","ParentGroupId":"parent_group_id",
         "Color":"color","Rank":"rank"},
        conflict=["tenant_id","aronium_id"]),
    "DocumentType": _t("ar_document_types",
        {"Id":"aronium_id","Name":"name","Code":"code",
         "DocumentCategoryId":"document_category_id","WarehouseId":"warehouse_id",
         "StockDirection":"stock_direction","EditorType":"editor_type",
         "PriceType":"price_type","LanguageKey":"language_key"},
        conflict=["tenant_id","aronium_id"]),
    "PaymentType": _t("ar_payment_types",
        {"Id":"aronium_id","Name":"name","Code":"code",
         "IsCustomerRequired":"is_customer_required","IsFiscal":"is_fiscal",
         "IsSlipRequired":"is_slip_required","IsChangeAllowed":"is_change_allowed",
         "Ordinal":"ordinal","IsEnabled":"is_enabled","IsQuickPayment":"is_quick_payment",
         "OpenCashDrawer":"open_cash_drawer","ShortcutKey":"shortcut_key",
         "MarkAsPaid":"mark_as_paid"},
        conflict=["tenant_id","aronium_id"]),
    "FiscalItem": _t("ar_fiscal_items",
        {"PLU":"plu","Name":"name","VAT":"vat"},
        conflict=["tenant_id","plu"], pk_col="plu"),
    "Counter": _t("ar_counters",
        {"Name":"name","Value":"value"},
        conflict=["tenant_id","name"], pk_col="name"),
    "FloorPlan": _t("ar_floor_plans",
        {"Id":"aronium_id","Name":"name","Color":"color"},
        conflict=["tenant_id","aronium_id"]),
    "FloorPlanTable": _t("ar_floor_plan_tables",
        {"Id":"aronium_id","Name":"name","FloorPlanId":"floor_plan_id",
         "PositionX":"position_x","PositionY":"position_y",
         "Width":"width","Height":"height","IsRound":"is_round"},
        conflict=["tenant_id","aronium_id"]),

    # ----- customers / products -----
    "Customer": _t("ar_customers",
        {"Id":"aronium_id","Code":"code","Name":"name","TaxNumber":"tax_number",
         "Address":"address","PostalCode":"postal_code","City":"city",
         "CountryId":"country_id","DateCreated":"date_created","DateUpdated":"date_updated",
         "Email":"email","PhoneNumber":"phone_number","IsEnabled":"is_enabled",
         "IsCustomer":"is_customer","IsSupplier":"is_supplier",
         "DueDatePeriod":"due_date_period","StreetName":"street_name",
         "AdditionalStreetName":"additional_street_name","BuildingNumber":"building_number",
         "PlotIdentification":"plot_identification","CitySubdivisionName":"city_subdivision_name",
         "CountrySubentity":"country_subentity","IsTaxExempt":"is_tax_exempt"},
        conflict=["tenant_id","aronium_id"]),
    "Product": _t("ar_products",
        {"Id":"aronium_id","ProductGroupId":"product_group_id","Name":"name","Code":"code",
         "PLU":"plu","MeasurementUnit":"measurement_unit","Price":"price",
         "IsTaxInclusivePrice":"is_tax_inclusive_price","CurrencyId":"currency_id",
         "IsPriceChangeAllowed":"is_price_change_allowed","IsService":"is_service",
         "IsUsingDefaultQuantity":"is_using_default_quantity","IsEnabled":"is_enabled",
         "Description":"description","DateCreated":"date_created","DateUpdated":"date_updated",
         "Cost":"cost","Markup":"markup","Color":"color","AgeRestriction":"age_restriction",
         "LastPurchasePrice":"last_purchase_price","Rank":"rank"},
        conflict=["tenant_id","aronium_id"]),
    "Barcode": _t("ar_barcodes",
        {"Id":"aronium_id","ProductId":"product_id","Value":"value"},
        conflict=["tenant_id","aronium_id"]),
    "Stock": _t("ar_stock",
        {"Id":"aronium_id","ProductId":"product_id","WarehouseId":"warehouse_id",
         "Quantity":"quantity"},
        conflict=["tenant_id","aronium_id"]),

    # ----- documents & children -----
    "Document": _t("ar_documents",
        {"Id":"aronium_id","Number":"number","UserId":"user_id","CustomerId":"customer_id",
         "OrderNumber":"order_number","Date":"doc_date","StockDate":"stock_date",
         "Total":"total","IsClockedOut":"is_clocked_out",
         "DocumentTypeId":"document_type_id","WarehouseId":"warehouse_id",
         "ReferenceDocumentNumber":"reference_document_number",
         "DateCreated":"date_created","DateUpdated":"date_updated",
         "InternalNote":"internal_note","Note":"note","DueDate":"due_date",
         "Discount":"discount","DiscountType":"discount_type",
         "PaidStatus":"paid_status","DiscountApplyRule":"discount_apply_rule",
         "ServiceType":"service_type"},
        conflict=["tenant_id","aronium_id"]),
    "DocumentItem": _t("ar_document_items",
        {"Id":"aronium_id","DocumentId":"document_id","ProductId":"product_id",
         "Quantity":"quantity","ExpectedQuantity":"expected_quantity",
         "PriceBeforeTax":"price_before_tax","Price":"price","Discount":"discount",
         "DiscountType":"discount_type","ProductCost":"product_cost",
         "PriceBeforeTaxAfterDiscount":"price_before_tax_after_discount",
         "PriceAfterDiscount":"price_after_discount","Total":"total",
         "TotalAfterDocumentDiscount":"total_after_document_discount",
         "DiscountApplyRule":"discount_apply_rule"},
        conflict=["tenant_id","aronium_id"]),
    "DocumentItemTax": _t("ar_document_item_taxes",
        {"DocumentItemId":"document_item_id","TaxId":"tax_id","Amount":"amount"},
        conflict=["tenant_id","document_item_id","tax_id"],
        pk_composite_cols=["document_item_id","tax_id"]),
    "Payment": _t("ar_payments",
        {"Id":"aronium_id","DocumentId":"document_id","PaymentTypeId":"payment_type_id",
         "Amount":"amount","Date":"pay_date","UserId":"user_id",
         "ZReportId":"z_report_id","DateCreated":"date_created"},
        conflict=["tenant_id","aronium_id"]),

    # ----- POS orders / loyalty / discounts -----
    "PosOrder": _t("ar_pos_orders",
        {"Id":"aronium_id","UserId":"user_id","Number":"number","Discount":"discount",
         "DiscountType":"discount_type","Total":"total","CustomerId":"customer_id",
         "ServiceType":"service_type"},
        conflict=["tenant_id","aronium_id"]),
    "PosOrderItem": _t("ar_pos_order_items",
        {"Id":"aronium_id","PosOrderId":"pos_order_id","ProductId":"product_id",
         "RoundNumber":"round_number","Quantity":"quantity","Price":"price",
         "IsLocked":"is_locked","Discount":"discount","DiscountType":"discount_type",
         "IsFeatured":"is_featured","VoidedBy":"voided_by","Comment":"comment",
         "DateCreated":"date_created","Bundle":"bundle",
         "DiscountAppliedType":"discount_applied_type"},
        conflict=["tenant_id","aronium_id"]),
    "LoyaltyCard": _t("ar_loyalty_cards",
        {"Id":"aronium_id","CustomerId":"customer_id","CardNumber":"card_number"},
        conflict=["tenant_id","aronium_id"]),
    "CustomerDiscount": _t("ar_customer_discounts",
        {"Id":"aronium_id","CustomerId":"customer_id","Type":"type",
         "Uid":"uid","Value":"value"},
        conflict=["tenant_id","aronium_id"]),
}


def validate_table(name: str) -> Dict[str, Any]:
    t = TABLE_MAP.get(name)
    if t is None:
        raise HTTPException(400, f"unknown table: {name}")
    return t


def project_row(tdef: Dict[str, Any], raw: Dict[str, Any]) -> List[Any]:
    """Return values aligned with tdef['columns'].values() order, dropping unknown keys."""
    return [raw.get(src) for src in tdef["columns"].keys()]
