package shopify

// Define scopes supported by Shopify.
// See: https://help.shopify.com/en/api/getting-started/authentication/oauth/scopes#authenticated-access-scopes
const (
	ScopeReadContent                 = "read_content"
	ScopeWriteContent                = "write_content"
	ScopeReadThemes                  = "read_themes"
	ScopeWriteThemes                 = "write_themes"
	ScopeReadProducts                = "read_products"
	ScopeWriteProducts               = "write_products"
	ScopeReadProductListings         = "read_product_listings"
	ScopeReadCustomers               = "read_customers"
	ScopeWriteCustomers              = "write_customers"
	ScopeReadOrders                  = "read_orders"
	ScopeWriteOrders                 = "write_orders"
	ScopeReadDrafOrders              = "read_draft_orders"
	ScopeWriteDrafOrders             = "write_draft_orders"
	ScopeReadInventory               = "read_inventory"
	ScopeWriteInventory              = "write_inventory"
	ScopeReadLocations               = "read_locations"
	ScopeReadScriptTags              = "read_script_tags"
	ScopeWriteScriptTags             = "write_script_tags"
	ScopeReadFulfillments            = "read_fulfillments"
	ScopeWriteFulfillments           = "write_fulfillments"
	ScopeReadShipping                = "read_shipping"
	ScopeWriteShipping               = "write_shipping"
	ScopeReadAnalytics               = "read_analytics"
	ScopeReadUsers                   = "read_users"
	ScopeWriteUsers                  = "write_users"
	ScopeReadCheckouts               = "read_checkouts"
	ScopeWriteCheckouts              = "write_checkouts"
	ScopeReadReports                 = "read_reports"
	ScopeWriteReports                = "write_reports"
	ScopeReadPriceRules              = "read_price_rules"
	ScopeWritePriceRules             = "write_price_rules"
	ScopeMarketingEvents             = "read_marketing_events"
	ScopeWriteMarketingEvents        = "write_marketing_events"
	ScopeReadResourceFeedbacks       = "read_resource_feedbacks"
	ScopeWriteResourceFeedbacks      = "write_resource_feedbacks"
	ScopeReadShopifyPaymentsPayouts  = "read_shopify_payments_payouts"
	ScopeReadShopifyPaymentsDisputes = "read_shopify_payments_disputes"

	// Special:
	// Grants access to all orders rather than the default window of 60 days worth of orders.
	// This OAuth scope is used in conjunction with read_orders, or write_orders. You need to request
	// this scope from your Partner Dashboard before adding it to your app.
	ScopeReadAllOrders = "read_all_orders"
)
