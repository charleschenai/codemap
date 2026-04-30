pub(crate) mod common;
mod pe;
mod schema;
mod web;

// Re-export all public action functions so dispatch works unchanged
pub use pe::{pe_strings, pe_exports, pe_imports, pe_resources, pe_debug, pe_sections, dotnet_meta, binary_diff};
pub use schema::{clarion_schema, dbf_schema, sql_extract};
pub use web::{web_api, web_dom, web_sitemap, web_blueprint, js_api_extract};
