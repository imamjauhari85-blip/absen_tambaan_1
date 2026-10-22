
-- audit_keamanan_supabase_020.sql
-- HANYA BACA (SELECT).
-- Tujuan: inventarisasi keamanan schema public sebelum migrasi 020.
-- Tidak mengubah tabel, data, privilege, atau konfigurasi database.

\echo '=== 1. INFORMASI DATABASE ==='

SELECT
    current_database() AS database_name,
    current_user AS current_user,
    current_setting('server_version') AS postgres_version,
    current_setting('transaction_read_only') AS transaction_read_only;

\echo '=== 2. SELURUH TABEL PUBLIC DAN STATUS RLS ==='

SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    CASE c.relkind
        WHEN 'r' THEN 'TABLE'
        WHEN 'p' THEN 'PARTITIONED TABLE'
        WHEN 'v' THEN 'VIEW'
        WHEN 'm' THEN 'MATERIALIZED VIEW'
        WHEN 'f' THEN 'FOREIGN TABLE'
        ELSE c.relkind::text
    END AS object_type,
    c.relrowsecurity AS rls_enabled,
    c.relforcerowsecurity AS rls_forced,
    pg_get_userbyid(c.relowner) AS owner
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY object_type, table_name;

\echo '=== 3. PRIVILEGE ROLE PADA SELURUH TABEL PUBLIC ==='

WITH roles(role_name) AS (
    VALUES
        ('PUBLIC'),
        ('anon'),
        ('authenticated'),
        ('service_role')
),
objects AS (
    SELECT
        c.oid,
        c.relname,
        CASE c.relkind
            WHEN 'r' THEN 'TABLE'
            WHEN 'p' THEN 'PARTITIONED TABLE'
            WHEN 'v' THEN 'VIEW'
            WHEN 'm' THEN 'MATERIALIZED VIEW'
            WHEN 'f' THEN 'FOREIGN TABLE'
        END AS object_type
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
)
SELECT
    o.object_type,
    o.relname AS object_name,
    r.role_name,
    has_table_privilege(r.role_name, o.oid, 'SELECT') AS can_select,
    has_table_privilege(r.role_name, o.oid, 'INSERT') AS can_insert,
    has_table_privilege(r.role_name, o.oid, 'UPDATE') AS can_update,
    has_table_privilege(r.role_name, o.oid, 'DELETE') AS can_delete,
    has_table_privilege(r.role_name, o.oid, 'TRUNCATE') AS can_truncate,
    has_table_privilege(r.role_name, o.oid, 'REFERENCES') AS can_references,
    has_table_privilege(r.role_name, o.oid, 'TRIGGER') AS can_trigger
FROM objects o
CROSS JOIN roles r
ORDER BY o.relname, r.role_name;

\echo '=== 4. PRIVILEGE SEQUENCE PUBLIC ==='

WITH roles(role_name) AS (
    VALUES ('PUBLIC'), ('anon'), ('authenticated'), ('service_role')
)
SELECT
    s.sequence_schema,
    s.sequence_name,
    r.role_name,
    has_sequence_privilege(r.role_name,
        format('%I.%I', s.sequence_schema, s.sequence_name),
        'USAGE') AS can_usage,
    has_sequence_privilege(r.role_name,
        format('%I.%I', s.sequence_schema, s.sequence_name),
        'SELECT') AS can_select,
    has_sequence_privilege(r.role_name,
        format('%I.%I', s.sequence_schema, s.sequence_name),
        'UPDATE') AS can_update
FROM information_schema.sequences s
CROSS JOIN roles r
WHERE s.sequence_schema = 'public'
ORDER BY s.sequence_name, r.role_name;

\echo '=== 5. PRIVILEGE SCHEMA PUBLIC ==='

WITH roles(role_name) AS (
    VALUES ('PUBLIC'), ('anon'), ('authenticated'), ('service_role')
)
SELECT
    role_name,
    has_schema_privilege(role_name, 'public', 'USAGE') AS can_usage,
    has_schema_privilege(role_name, 'public', 'CREATE') AS can_create
FROM roles
ORDER BY role_name;

\echo '=== 6. DEFAULT PRIVILEGES PUBLIC ==='

SELECT
    pg_get_userbyid(d.defaclrole) AS grantor,
    COALESCE(r.rolname, 'PUBLIC') AS grantee,
    d.defaclobjtype AS object_type,
    d.defaclacl AS default_acl
FROM pg_default_acl d
JOIN pg_namespace n ON n.oid = d.defaclnamespace
LEFT JOIN pg_roles r ON r.oid = ANY (
    ARRAY(
        SELECT CASE
            WHEN x.grantee = 0 THEN NULL
            ELSE x.grantee
        END
        FROM aclexplode(d.defaclacl) x
    )
)
WHERE n.nspname = 'public'
ORDER BY grantor, object_type, grantee;

\echo '=== 7. POLICY RLS YANG SUDAH ADA ==='

SELECT
    schemaname,
    tablename,
    policyname,
    permissive,
    roles,
    cmd,
    qual,
    with_check
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;

\echo '=== 8. AKHIR AUDIT ==='
SELECT
    current_setting('transaction_read_only') AS transaction_read_only,
    now() AS audit_time;
