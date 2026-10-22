
-- audit_keamanan_fix.sql
-- HANYA BACA. Tidak mengubah privilege atau objek database.

\echo '=== A. HAK AKSES EFEKTIF PADA TABEL ==='

SELECT
    c.relname AS table_name,
    r.role_name,
    has_table_privilege(r.role_name, c.oid, 'SELECT') AS can_select,
    has_table_privilege(r.role_name, c.oid, 'INSERT') AS can_insert,
    has_table_privilege(r.role_name, c.oid, 'UPDATE') AS can_update,
    has_table_privilege(r.role_name, c.oid, 'DELETE') AS can_delete,
    has_table_privilege(r.role_name, c.oid, 'TRUNCATE') AS can_truncate
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN (
    VALUES ('anon'), ('authenticated'), ('service_role')
) AS r(role_name)
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY c.relname, r.role_name;

\echo '=== B. GRANT LANGSUNG KEPADA PUBLIC PADA TABEL ==='

SELECT
    c.relname AS object_name,
    x.privilege_type,
    x.is_grantable
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(
    COALESCE(c.relacl, acldefault('r', c.relowner))
) x
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND x.grantee = 0
ORDER BY c.relname, x.privilege_type;

\echo '=== C. HAK AKSES SEQUENCE ==='

SELECT
    c.relname AS sequence_name,
    r.role_name,
    has_sequence_privilege(r.role_name, c.oid, 'USAGE') AS can_usage,
    has_sequence_privilege(r.role_name, c.oid, 'SELECT') AS can_select,
    has_sequence_privilege(r.role_name, c.oid, 'UPDATE') AS can_update
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN (
    VALUES ('anon'), ('authenticated'), ('service_role')
) AS r(role_name)
WHERE n.nspname = 'public'
  AND c.relkind = 'S'
ORDER BY c.relname, r.role_name;

\echo '=== D. GRANT LANGSUNG KEPADA PUBLIC PADA SEQUENCE ==='

SELECT
    c.relname AS sequence_name,
    x.privilege_type,
    x.is_grantable
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(
    COALESCE(c.relacl, acldefault('S', c.relowner))
) x
WHERE n.nspname = 'public'
  AND c.relkind = 'S'
  AND x.grantee = 0
ORDER BY c.relname, x.privilege_type;

\echo '=== E. HAK AKSES SCHEMA PUBLIC ==='

SELECT
    r.role_name,
    has_schema_privilege(r.role_name, 'public', 'USAGE') AS can_usage,
    has_schema_privilege(r.role_name, 'public', 'CREATE') AS can_create
FROM (
    VALUES ('anon'), ('authenticated'), ('service_role')
) AS r(role_name);

\echo '=== F. GRANT LANGSUNG KEPADA PUBLIC PADA SCHEMA ==='

SELECT
    x.privilege_type,
    x.is_grantable
FROM pg_namespace n
CROSS JOIN LATERAL aclexplode(
    COALESCE(n.nspacl, acldefault('n', n.nspowner))
) x
WHERE n.nspname = 'public'
  AND x.grantee = 0
ORDER BY x.privilege_type;

\echo '=== G. AKHIR AUDIT ==='

SELECT
    current_setting('transaction_read_only') AS transaction_read_only,
    now() AS audit_time;
