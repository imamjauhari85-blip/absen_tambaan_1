-- audit_preflight_019_v2.sql — HANYA BACA (SELECT). Aman untuk database produksi.
-- Menggantikan audit_preflight_019.sql (v1). Perbedaan utama:
--   * Tidak dibungkus BEGIN/ROLLBACK: satu galat tidak lagi menggagalkan statement sesudahnya, dan
--     Supabase SQL Editor (yang hanya menampilkan hasil statement TERAKHIR) tidak berakhir kosong.
--   * Bagian 8 memakai to_regclass(): tidak error kalau tabel tidak ada; juga memeriksa index/constraint/tipe.
--   * absensi_setting dibaca dengan "select *" (tidak menyebut nama kolom yang mungkin belum ada).
--   * Tambahan: hak service_role, USAGE schema, role/exposed schemas, extension, default ACL, peran RLS bypass.
--
-- CARA PAKAI
--   psql (disarankan, hasil lengkap):
--     PGOPTIONS="-c default_transaction_read_only=on" psql -X "host=... port=5432 dbname=postgres user=postgres.<ref> sslmode=require" \
--       -f audit_preflight_019_v2.sql > hasil_preflight.txt 2>&1
--     (password diketik di prompt; jangan ditempel ke skrip/riwayat shell)
--   Supabase SQL Editor: salin SATU blok "-- N." per run (hanya hasil terakhir yang tampil).
--
-- Jika sebuah blok menghasilkan galat "relation/column ... does not exist", itu adalah TEMUAN audit
-- (skema produksi berbeda dari repo) — catat pesan galatnya, lanjutkan ke blok berikutnya.

-- [psql saja] pengaman tambahan tingkat sesi: seluruh statement di sesi ini ditolak bila mencoba menulis.
set default_transaction_read_only = on;
set statement_timeout = '30s';

-- 0. Identitas server dan role ---------------------------------------------------------------------
select current_database() as db, current_user as role_saat_ini,
       current_setting('server_version_num')::int as versi_num,
       current_setting('TimeZone') as timezone, version();

-- Role penting. Harapan: service_role rolbypassrls = true (fungsi 019 berjalan sebagai invoker).
select rolname, rolbypassrls, rolcanlogin, rolsuper
from pg_roles
where rolname in ('postgres','anon','authenticated','service_role','authenticator','supabase_admin')
order by rolname;

-- 1. Kolom aktual (HARUS dijalankan sebagai role pemilik tabel, mis. postgres; kalau hasil kosong, role Anda tidak punya akses)
select c.table_name, c.ordinal_position as no, c.column_name, c.data_type, c.is_nullable,
       c.column_default, c.is_identity, c.identity_generation
from information_schema.columns c
where c.table_schema = 'public'
  and c.table_name in ('absensi','students','users','absensi_setting','absensi_log','log_aktivitas')
order by c.table_name, c.ordinal_position;

-- 2. Constraint (PK, FK, UNIQUE, CHECK) -------------------------------------------------------------
select conrelid::regclass::text as tabel, conname, contype, pg_get_constraintdef(oid) as definisi
from pg_constraint
where conrelid in (select oid from pg_class
                    where relnamespace = 'public'::regnamespace
                      and relname in ('absensi','students','users','absensi_setting','absensi_log','log_aktivitas'))
order by 1, contype, conname;

-- 3. Index (perhatikan kemungkinan DUA unique (siswa_id, tanggal) di absensi) --------------------------
select tablename, indexname, indexdef
from pg_indexes
where schemaname = 'public'
  and tablename in ('absensi','students','users','absensi_setting','absensi_log','log_aktivitas')
order by tablename, indexname;

-- 4. Trigger non-internal di schema public (termasuk Database Webhook: cari supabase_functions.http_request)
select c.relname as tabel, t.tgname, t.tgenabled, pg_get_triggerdef(t.oid) as definisi
from pg_trigger t join pg_class c on c.oid = t.tgrelid
where not t.tgisinternal and c.relnamespace = 'public'::regnamespace
order by 1, 2;

-- 5a. Status RLS semua tabel public ---------------------------------------------------------------------
select c.relname, c.relkind, c.relrowsecurity as rls_aktif, c.relforcerowsecurity as rls_force
from pg_class c
where c.relnamespace = 'public'::regnamespace and c.relkind in ('r','p')
order by c.relname;

-- 5b. Policy RLS ------------------------------------------------------------------------------------------
select schemaname, tablename, policyname, roles, cmd, qual, with_check
from pg_policies where schemaname = 'public' order by tablename, policyname;

-- 6a. Hak tabel per role (hanya role yang ada; tidak error bila role tidak ada) ------------------------------
-- Harapan: anon & authenticated semua false; service_role semua true (fungsi 019 SECURITY INVOKER).
select c.relname, r.rolname,
       has_table_privilege(r.oid, c.oid, 'select') as p_select,
       has_table_privilege(r.oid, c.oid, 'insert') as p_insert,
       has_table_privilege(r.oid, c.oid, 'update') as p_update,
       has_table_privilege(r.oid, c.oid, 'delete') as p_delete
from pg_class c
join pg_roles r on r.rolname in ('anon','authenticated','service_role')
where c.relnamespace = 'public'::regnamespace and c.relkind in ('r','p')
  and c.relname in ('absensi','students','users','absensi_setting','absensi_log','log_aktivitas')
order by c.relname, r.rolname;

-- 6b. USAGE pada schema public per role -----------------------------------------------------------------------
select r.rolname, has_schema_privilege(r.oid, 'public', 'usage') as usage_public
from pg_roles r where r.rolname in ('anon','authenticated','service_role') order by 1;

-- 6c. Schema yang diekspos PostgREST (kalau kosong: Dashboard > Settings > API > Exposed schemas) ----------------
select rolname, rolconfig from pg_roles where rolname = 'authenticator';

-- 7. Semua fungsi di schema public: pemilik, SECURITY DEFINER, ACL --------------------------------------------
-- Konvensi repo (013/014/016/017): tanpa SECURITY DEFINER, EXECUTE hanya service_role.
select p.proname, pg_get_function_identity_arguments(p.oid) as argumen,
       p.prosecdef as security_definer, pg_get_userbyid(p.proowner) as pemilik, p.proacl::text as acl
from pg_proc p
where p.pronamespace = 'public'::regnamespace
order by p.proname;

-- 8. Benturan nama dengan migrasi 019 (HASIL HARUS KOSONG) ----------------------------------------------------
select 'fungsi' as jenis, p.proname::text as nama
  from pg_proc p
 where p.pronamespace = 'public'::regnamespace
   and p.proname in ('absensi_naikkan_rev','absensi_snapshot','absensi_ringkas',
                     'edit_manual_absensi','pulihkan_edit_manual','daftar_bisa_pulihkan')
union all
select 'tabel', c.relname::text
  from pg_class c where c.relnamespace = 'public'::regnamespace and c.relname = 'absensi_edit_manual'
union all
select 'tipe', t.typname::text
  from pg_type t where t.typnamespace = 'public'::regnamespace and t.typname = 'absensi_edit_manual'
union all
select 'kolom absensi.rev', a.attname::text
  from pg_attribute a where a.attrelid = to_regclass('public.absensi') and a.attname = 'rev' and not a.attisdropped
union all
select 'kolom absensi_setting.masa_pulihkan_hari', a.attname::text
  from pg_attribute a where a.attrelid = to_regclass('public.absensi_setting')
   and a.attname = 'masa_pulihkan_hari' and not a.attisdropped
union all
select 'trigger', t.tgname::text from pg_trigger t where t.tgname = 'trg_absensi_naikkan_rev'
union all
select 'index', i.indexname::text from pg_indexes i where i.indexname = 'idx_absensi_edit_manual_siswa_tgl'
union all
select 'constraint', k.conname::text from pg_constraint k where k.conname = 'absensi_setting_masa_pulihkan_chk';

-- 9. Fungsi lain yang menyentuh absensi (mungkin dibuat manual dan tidak ada di repo) -------------------------
select p.proname, pg_get_function_identity_arguments(p.oid) as argumen
from pg_proc p
where p.pronamespace = 'public'::regnamespace and p.prosrc ilike '%absensi%'
order by 1;

-- 10a. Event trigger (bawaan Supabase seperti pgrst_ddl_watch itu normal) --------------------------------------
select evtname, evtevent, evtfoid::regproc::text as fungsi from pg_event_trigger order by 1;

-- 10b. Extension (cari pg_cron / pg_net; kalau pg_cron ada, jalankan manual: select jobid, schedule, command from cron.job;) ---
select extname, extversion from pg_extension order by 1;

-- 10c. Default ACL (hak otomatis untuk objek baru, termasuk fungsi/tabel yang akan dibuat 019) ---------------------
select pg_get_userbyid(defaclrole) as pemilik, defaclnamespace::regnamespace::text as schema_target,
       defaclobjtype as jenis, defaclacl::text as acl
from pg_default_acl order by 1, 2, 3;

-- 11a. Jumlah baris (eksak) ---------------------------------------------------------------------------------------
select 'absensi' as tabel, count(*) as baris from public.absensi
union all select 'absensi_log', count(*) from public.absensi_log
union all select 'log_aktivitas', count(*) from public.log_aktivitas
union all select 'students', count(*) from public.students
union all select 'users', count(*) from public.users;

-- 11b. Ukuran tabel (untuk menilai lama ALTER TABLE) ---------------------------------------------------------------
select c.relname, pg_size_pretty(pg_total_relation_size(c.oid)) as ukuran
from pg_class c
where c.relnamespace = 'public'::regnamespace
  and c.relname in ('absensi','absensi_log','log_aktivitas','students','users')
order by c.relname;

-- 11c. absensi_setting: harus TEPAT 1 baris (fungsi 019 memakai "order by id limit 1") ----------------------------
select * from public.absensi_setting order by 1;

-- 11d. Duplikat siswa+tanggal: harus 0 baris ------------------------------------------------------------------------
select siswa_id, tanggal, count(*) as jumlah
from public.absensi group by 1, 2 having count(*) > 1 limit 20;

-- 11e. Sebaran status -------------------------------------------------------------------------------------------------
select status, count(*) as jumlah from public.absensi group by 1 order by 2 desc;

-- 11f. Jam terisi pada status non-hadir (baris lama yang tidak sesuai aturan jam baru: izin/sakit/alpha = jam kosong) --
select status,
       count(*) filter (where jam_masuk is not null or jam_pulang is not null) as dengan_jam,
       count(*) as total
from public.absensi group by 1 order by 1;

-- 11g. Lampiran dan tapel (galat "column ... does not exist" di sini = migrasi 008/001 belum sesuai) --------------
select count(*) as total,
       count(*) filter (where lampiran is not null and lampiran <> '') as ada_lampiran,
       count(*) filter (where tapel is null) as tapel_null
from public.absensi;

-- 11h. Host lampiran yang benar-benar tersimpan (dasar whitelist host Cloudinary; hanya host, bukan URL lengkap) ----
select coalesce(substring(lampiran from '^[A-Za-z]+://[^/]+'), '(kosong)') as host, count(*) as jumlah
from public.absensi
where lampiran is not null and lampiran <> ''
group by 1 order by 2 desc;
