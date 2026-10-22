
-- HANYA BACA: audit fungsi dan hak EXECUTE.

\echo '=== A. DAFTAR FUNGSI PUBLIC DAN HAK EXECUTE ==='

SELECT
    p.oid::regprocedure AS function_signature,
    pg_get_userbyid(p.proowner) AS owner,
    l.lanname AS language,
    p.prosecdef AS security_definer,
    has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_execute,
    has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authenticated_execute,
    has_function_privilege('service_role', p.oid, 'EXECUTE') AS service_role_execute
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE n.nspname = 'public'
ORDER BY p.proname, p.oid::regprocedure::text;

\echo '=== B. GRANT EXECUTE LANGSUNG KEPADA PUBLIC ==='

SELECT
    p.oid::regprocedure AS function_signature,
    x.privilege_type,
    x.is_grantable
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
CROSS JOIN LATERAL aclexplode(
    COALESCE(p.proacl, acldefault('f', p.proowner))
) x
WHERE n.nspname = 'public'
  AND x.grantee = 0
  AND x.privilege_type = 'EXECUTE'
ORDER BY p.proname;

\echo '=== C. TRIGGER PADA TABEL PUBLIC ==='

SELECT
    c.relname AS table_name,
    t.tgname AS trigger_name,
    p.oid::regprocedure AS trigger_function,
    t.tgenabled AS trigger_status
FROM pg_trigger t
JOIN pg_class c ON c.oid = t.tgrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_proc p ON p.oid = t.tgfoid
WHERE n.nspname = 'public'
  AND NOT t.tgisinternal
ORDER BY c.relname, t.tgname;

\echo '=== D. AKHIR AUDIT ==='

SELECT current_setting('transaction_read_only') AS transaction_read_only;
