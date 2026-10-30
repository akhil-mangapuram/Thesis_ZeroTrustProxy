-- Enterprise Public Catalog Database Schema
CREATE TABLE IF NOT EXISTS public_catalog (
    item_id INTEGER PRIMARY KEY,
    sku_code TEXT NOT NULL UNIQUE,
    product_name TEXT NOT NULL,
    is_active BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS public_releases (
    release_id INTEGER PRIMARY KEY,
    version_string TEXT NOT NULL,
    release_date TEXT NOT NULL
);
