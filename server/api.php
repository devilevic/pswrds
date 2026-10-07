<?php
/**
 * pswrds storage API.
 *
 * Stores only encrypted, fixed-size slots. It never receives a passphrase or a
 * decryption key, and it cannot tell a wallet slot from a delete command or an
 * unused slot. Writes require the vault's write token, which lives inside the
 * encrypted slots, so only someone who can unlock a slot can change the vault.
 *
 *   GET  api.php?op=ping
 *   GET  api.php?op=vault&id=<64 hex>
 *   POST {"op":"create","id":..,"token":..,"header":{"iter":..,"salt":..,"n":8},"slots":[8 x base64],"invite":"9CA1B0" (optional)}
 *
 * Invitation codes are single-use. The server records only that a code was used, never which
 * vault used it or when, so the database can't tell a vault created with a code from one without.
 *   POST {"op":"slot","id":..,"token":..,"i":0-7,"d":base64,"v":n}   v: the slot version the app last saw (a random
 *        number that changes on every save, never a counter);
 *        if the slot changed since (another device saved), the answer is 409 "stale" and nothing is written.
 *   POST {"op":"slots","id":..,"token":..,"slots":{"i":base64,..},"new_token":.. (optional)}   several at once, e.g. a passphrase change
 *   POST {"op":"delete","id":..,"token":..}
 *   POST {"op":"stats","pass":..}   admin statistics; password is 'admin_password' in pswrds-config.php
 *
 * Free tier and payments (only active when NOWPayments or BTCPay is set up in pswrds-config.php):
 *   GET  api.php?op=vault also returns "paid" and "limit" (records per wallet, null = unlimited).
 *        The limit is enforced by the app: the server can't see records, by design.
 *   POST {"op":"pay_start"}                         creates an invoice. No vault id is sent.
 *   POST {"op":"pay_check","invoice":..,"claim":..}  returns the invoice status, and the license code once settled.
 *   POST {"op":"redeem","id":..,"token":..,"code":..} applies a license code: the vault becomes paid for life.
 *   POST api.php?op=nowpayments_ipn                  NOWPayments' signed status callback (no X-Pswrds header).
 * The server never stores which vault a payment or license belongs to, only that a vault is paid.
 *
 * Invitation codes on request (from the extra-features page):
 *   GET  api.php?op=invite_challenge                 a small proof-of-work puzzle
 *   POST {"op":"invite_request","c":..,"nonce":..}   solved puzzle in, new invitation code out
 * Limited per IP (keyed hash, kept one day) and per day. No issue time is stored for a code.
 *
 * Statistics are aggregate counters only (vaults created with/without a code, deleted). No
 * per-vault flag is ever stored, so a single vault can't be classified from the database.
 */

declare(strict_types=1);

const NSLOTS     = 8;
const SLOT_B64   = 87420;   // base64 length of 12 + 65536 + 16 bytes
const RATE_LIMIT = 300;     // requests per IP per window
const RATE_WIN   = 600;     // window length in seconds
const POW_BITS   = 18;      // proof-of-work difficulty for invitation requests (about 2-5 seconds in a browser)
const POW_TTL    = 900;     // a puzzle must be solved within 15 minutes

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

function out(int $code, array $body = ['ok' => true]): void {
    http_response_code($code);
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
}

function config(): array {
    foreach ([dirname(__DIR__) . '/pswrds-config.php', __DIR__ . '/config.php'] as $f) {
        if (is_file($f)) {
            try { $c = require $f; }
            catch (Throwable $e) {
                // Usually a typo in pswrds-config.php: a missing comma or quote, or curly quotes from a word processor
                error_log('pswrds api: cannot read ' . basename($f) . ': ' . $e->getMessage());
                out(500, ['error' => 'config_syntax', 'line' => $e->getLine()]);
            }
            if (!is_array($c)) out(500, ['error' => 'config_syntax']);
            return $c;
        }
    }
    out(500, ['error' => 'config_missing']);
}

/** SHA-256 hashes of the valid invitation codes, from pswrds-invites.php (kept outside public_html). */
function invite_hashes(): array {
    foreach ([dirname(__DIR__) . '/pswrds-invites.php', __DIR__ . '/invites.php'] as $f) {
        if (is_file($f)) { $h = require $f; return is_array($h) ? $h : []; }
    }
    return [];
}

function db(array $cfg): PDO {
    try {
        $pdo = new PDO($cfg['dsn'], $cfg['user'] ?? null, $cfg['pass'] ?? null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    } catch (Throwable $e) {
        // Wrong database name, user or password in pswrds-config.php (details go to error_log only)
        error_log('pswrds api: database connection failed: ' . $e->getMessage());
        out(500, ['error' => 'db_connect_failed']);
    }
    try { create_tables($pdo); migrate($pdo, $cfg); } catch (Throwable $e) {
        // The database user lacks CREATE privileges
        error_log('pswrds api: creating tables failed: ' . $e->getMessage());
        out(500, ['error' => 'db_tables_failed']);
    }
    return $pdo;
}

function create_tables(PDO $pdo): void {
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_vaults (
        id CHAR(64) NOT NULL PRIMARY KEY,
        token_hash CHAR(64) NOT NULL,
        iter INT NOT NULL,
        salt VARCHAR(32) NOT NULL,
        n INT NOT NULL,
        created_at INT NOT NULL,
        paid TINYINT NOT NULL DEFAULT 0)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_slots (
        vault_id CHAR(64) NOT NULL,
        i INT NOT NULL,
        d MEDIUMTEXT NOT NULL,
        v INT NOT NULL DEFAULT 0,
        PRIMARY KEY (vault_id, i))');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_stats (
        k VARCHAR(32) NOT NULL PRIMARY KEY,
        n INT NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_invites_used (
        h CHAR(64) NOT NULL PRIMARY KEY)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_hits (
        k CHAR(64) NOT NULL PRIMARY KEY,
        win INT NOT NULL,
        n INT NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_invites_issued (
        h CHAR(64) NOT NULL PRIMARY KEY)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_limits (
        k CHAR(64) NOT NULL PRIMARY KEY,
        day INT NOT NULL,
        n INT NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_pow_used (
        h CHAR(64) NOT NULL PRIMARY KEY,
        exp INT NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_orders (
        invoice VARCHAR(64) NOT NULL PRIMARY KEY,
        claim_hash CHAR(64) NOT NULL,
        created_at INT NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT \'new\',
        order_ref VARCHAR(32) NOT NULL DEFAULT \'\')');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_meta (
        k VARCHAR(32) NOT NULL PRIMARY KEY,
        v VARCHAR(255) NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS pswrds_licenses (
        h CHAR(64) NOT NULL PRIMARY KEY,
        used TINYINT NOT NULL DEFAULT 0)');
}

function stat_get(PDO $pdo, string $k): ?int {
    $q = $pdo->prepare('SELECT n FROM pswrds_stats WHERE k = ?');
    $q->execute([$k]);
    $v = $q->fetchColumn();
    return $v === false ? null : (int)$v;
}

function meta_set(PDO $pdo, string $k, string $v): void {
    $u = $pdo->prepare('UPDATE pswrds_meta SET v = ? WHERE k = ?');
    $u->execute([substr($v, 0, 255), $k]);
    if ($u->rowCount() === 0) {
        try { $pdo->prepare('INSERT INTO pswrds_meta (k, v) VALUES (?, ?)')->execute([$k, substr($v, 0, 255)]); }
        catch (PDOException $e) { /* parallel insert, fine */ }
    }
}

function stat_set(PDO $pdo, string $k, int $n): void {
    $u = $pdo->prepare('UPDATE pswrds_stats SET n = ? WHERE k = ?');
    $u->execute([$n, $k]);
    if ($u->rowCount() === 0) {
        try { $pdo->prepare('INSERT INTO pswrds_stats (k, n) VALUES (?, ?)')->execute([$k, $n]); }
        catch (PDOException $e) { /* parallel insert, fine */ }
    }
}

/** Upgrades older databases, and gives every vault that exists when payments are switched on lifetime access. */
function migrate(PDO $pdo, array $cfg): void {
    if ((stat_get($pdo, 'schema') ?? 1) < 2) {
        try { $pdo->exec('ALTER TABLE pswrds_vaults ADD COLUMN paid TINYINT NOT NULL DEFAULT 0'); }
        catch (Throwable $e) { /* column exists already */ }
        stat_set($pdo, 'schema', 2);
    }
    if ((stat_get($pdo, 'schema') ?? 1) < 3) {
        try { $pdo->exec("ALTER TABLE pswrds_orders ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'new'"); }
        catch (Throwable $e) { /* column exists already */ }
        stat_set($pdo, 'schema', 3);
    }
    if ((stat_get($pdo, 'schema') ?? 1) < 4) {
        try { $pdo->exec("ALTER TABLE pswrds_orders ADD COLUMN order_ref VARCHAR(32) NOT NULL DEFAULT ''"); }
        catch (Throwable $e) { /* column exists already */ }
        stat_set($pdo, 'schema', 4);
    }
    if ((stat_get($pdo, 'schema') ?? 1) < 5) {   // slot versions, so two devices can't overwrite each other's changes
        try { $pdo->exec('ALTER TABLE pswrds_slots ADD COLUMN v INT NOT NULL DEFAULT 0'); }
        catch (Throwable $e) { /* column exists already */ }
        stat_set($pdo, 'schema', 5);
    }
    if ((stat_get($pdo, 'schema') ?? 1) < 6) {
        // Slot versions become random numbers instead of counters: a counter showed how often each slot
        // had been saved, and so which slots are in use. Existing counters are replaced once.
        $rows = $pdo->query('SELECT vault_id, i FROM pswrds_slots')->fetchAll();
        $u = $pdo->prepare('UPDATE pswrds_slots SET v = ? WHERE vault_id = ? AND i = ?');
        foreach ($rows as $r) $u->execute([new_ver(), $r['vault_id'], (int)$r['i']]);
        stat_set($pdo, 'schema', 6);
    }
    if (payments_on($cfg) && stat_get($pdo, 'grandfathered') === null) {
        $n = $pdo->exec('UPDATE pswrds_vaults SET paid = 1');
        stat_set($pdo, 'grandfathered', (int)$n);
    }
}

/** 'nowpayments', 'btcpay', or '' when payments are off. NOWPayments wins if both are filled in. */
function provider(array $cfg): string {
    if (($cfg['nowpayments_key'] ?? '') !== '' && ($cfg['nowpayments_ipn_secret'] ?? '') !== '') return 'nowpayments';
    if (($cfg['btcpay_url'] ?? '') !== '' && ($cfg['btcpay_store'] ?? '') !== '' && ($cfg['btcpay_key'] ?? '') !== '') return 'btcpay';
    return '';
}

function payments_on(array $cfg): bool { return provider($cfg) !== ''; }

/** Records per wallet for a vault, or null for unlimited. */
function record_limit(array $cfg, bool $paid): ?int {
    return payments_on($cfg) && !$paid ? (int)($cfg['free_records'] ?? 10) : null;
}

function rate_limit(PDO $pdo, string $secret): void {
    $ip  = $_SERVER['REMOTE_ADDR'] ?? '0';
    $k   = hash_hmac('sha256', $ip, $secret);   // raw IPs are never stored
    $win = intdiv(time(), RATE_WIN);
    $row = $pdo->prepare('SELECT win, n FROM pswrds_hits WHERE k = ?');
    $row->execute([$k]);
    $r = $row->fetch();
    if (!$r) {
        try { $pdo->prepare('INSERT INTO pswrds_hits (k, win, n) VALUES (?, ?, 1)')->execute([$k, $win]); }
        catch (PDOException $e) { /* parallel insert, fine */ }
    } elseif ((int)$r['win'] !== $win) {
        $pdo->prepare('UPDATE pswrds_hits SET win = ?, n = 1 WHERE k = ?')->execute([$win, $k]);
    } elseif ((int)$r['n'] >= RATE_LIMIT) {
        out(429, ['error' => 'rate_limited']);
    } else {
        $pdo->prepare('UPDATE pswrds_hits SET n = n + 1 WHERE k = ?')->execute([$k]);
    }
    if (random_int(1, 200) === 1) {   // occasional cleanup of old windows
        $pdo->prepare('DELETE FROM pswrds_hits WHERE win < ?')->execute([$win - 1]);
    }
}

function bump(PDO $pdo, string $k): void {
    $u = $pdo->prepare('UPDATE pswrds_stats SET n = n + 1 WHERE k = ?');
    $u->execute([$k]);
    if ($u->rowCount() === 0) $pdo->prepare('INSERT INTO pswrds_stats (k, n) VALUES (?, 1)')->execute([$k]);
}

function admin_auth(array $cfg, $pass): void {
    $admin = (string)($cfg['admin_password'] ?? '');
    if (strlen($admin) < 12) out(403, ['error' => 'admin_not_set']);
    if (!is_string($pass) || !hash_equals(hash('sha256', $admin), hash('sha256', $pass))) {
        sleep(2);   // slows down password guessing
        out(403, ['error' => 'denied']);
    }
}

/** A license code made by hand, for support cases (for example a payment that arrived a little short). */
function admin_license(PDO $pdo, array $cfg, $pass): void {
    admin_auth($cfg, $pass);
    $s = '';
    for ($i = 0; $i < 16; $i++) $s .= LICENSE_ALPHABET[random_int(0, 31)];
    $pdo->prepare('INSERT INTO pswrds_licenses (h, used) VALUES (?, 0)')->execute([license_hash($s)]);
    bump($pdo, 'licenses_manual');
    out(200, ['code' => implode('-', str_split($s, 4))]);
}

function stats(PDO $pdo, array $cfg, $pass): void {
    admin_auth($cfg, $pass);
    $c = [];
    foreach ($pdo->query('SELECT k, n FROM pswrds_stats')->fetchAll() as $r) $c[$r['k']] = (int)$r['n'];
    $total = (int)$pdo->query('SELECT COUNT(*) FROM pswrds_vaults')->fetchColumn();
    $q = $pdo->prepare('SELECT created_at FROM pswrds_vaults WHERE created_at >= ? ORDER BY created_at DESC LIMIT 5000');
    $q->execute([time() - 90 * 86400]);
    $since = array_map('intval', $q->fetchAll(PDO::FETCH_COLUMN));
    $first = $pdo->query('SELECT MIN(created_at) FROM pswrds_vaults')->fetchColumn();
    $withCode = $c['created_invited'] ?? 0; $without = $c['created_plain'] ?? 0; $deleted = $c['deleted'] ?? 0;
    out(200, [
        'now' => time(),
        'total' => $total,
        'created_invited' => $withCode,
        'created_plain' => $without,
        'deleted' => $deleted,
        'before_tracking' => max(0, $total + $deleted - $withCode - $without),
        'invites_used' => (int)$pdo->query('SELECT COUNT(*) FROM pswrds_invites_used')->fetchColumn(),
        'invites_total' => count(invite_hashes()) + (int)$pdo->query('SELECT COUNT(*) FROM pswrds_invites_issued')->fetchColumn(),
        'first_created' => $first === null || $first === false ? null : (int)$first,
        'created_90d' => $since,
        'invites_issued' => $c['invites_issued'] ?? 0,
        'payments_on' => payments_on($cfg),
        'provider' => provider($cfg),
        'ipn_last_at' => $c['ipn_last_at'] ?? null,
        'ipn_last_ok' => isset($c['ipn_last_ok']) ? $c['ipn_last_ok'] === 1 : null,
        'ipn_last' => json_decode((string)($pdo->query("SELECT v FROM pswrds_meta WHERE k = 'ipn_last'")->fetchColumn() ?: 'null'), true),
        'paid_vaults' => (int)$pdo->query('SELECT COUNT(*) FROM pswrds_vaults WHERE paid = 1')->fetchColumn(),
        'grandfathered' => $c['grandfathered'] ?? null,
        'licenses_sold' => $c['licenses_sold'] ?? 0,
        'licenses_manual' => $c['licenses_manual'] ?? 0,
        'licenses_redeemed' => (int)$pdo->query('SELECT COUNT(*) FROM pswrds_licenses WHERE used = 1')->fetchColumn(),
        'price_usd' => (string)($cfg['price_usd'] ?? '20'),
        'free_records' => (int)($cfg['free_records'] ?? 10),
    ]);
}

/** A slot version is a random number that changes on every save. It only tells two devices apart that would
 *  otherwise overwrite each other's changes; unlike a counter, it says nothing about how often a slot was used. */
function new_ver(): int { return random_int(1, 2147483647); }

function slot_version(PDO $pdo, string $id, int $i): int {
    $q = $pdo->prepare('SELECT v FROM pswrds_slots WHERE vault_id = ? AND i = ?');
    $q->execute([$id, $i]);
    return (int)$q->fetchColumn();
}

function is_hex64($v): bool  { return is_string($v) && preg_match('/^[0-9a-f]{64}$/', $v) === 1; }
function is_slot($v): bool   { return is_string($v) && strlen($v) === SLOT_B64 && preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $v) === 1; }

function check_token(PDO $pdo, string $id, $token): void {
    if (!is_hex64($token)) out(403, ['error' => 'denied']);
    $q = $pdo->prepare('SELECT token_hash FROM pswrds_vaults WHERE id = ?');
    $q->execute([$id]);
    $h = $q->fetchColumn();
    if ($h === false) out(404, ['error' => 'not_found']);
    if (!hash_equals($h, hash('sha256', $token))) out(403, ['error' => 'denied']);
}

function ip_key(array $cfg, string $purpose): string {
    return hash_hmac('sha256', $purpose . ':' . ($_SERVER['REMOTE_ADDR'] ?? '0'), $cfg['secret'] ?? 'change-me');
}

/** Daily counter. Returns false when $k has already reached $max today. */
function under_limit(PDO $pdo, string $k, int $max): bool {
    $day = intdiv(time(), 86400);
    $q = $pdo->prepare('SELECT day, n FROM pswrds_limits WHERE k = ?');
    $q->execute([$k]);
    $r = $q->fetch();
    return !$r || (int)$r['day'] !== $day || (int)$r['n'] < $max;
}

function count_limit(PDO $pdo, string $k): void {
    $day = intdiv(time(), 86400);
    $u = $pdo->prepare('UPDATE pswrds_limits SET n = CASE WHEN day = ? THEN n + 1 ELSE 1 END, day = ? WHERE k = ?');
    $u->execute([$day, $day, $k]);
    if ($u->rowCount() === 0) {
        try { $pdo->prepare('INSERT INTO pswrds_limits (k, day, n) VALUES (?, ?, 1)')->execute([$k, $day]); }
        catch (PDOException $e) { $pdo->prepare('UPDATE pswrds_limits SET n = n + 1 WHERE k = ?')->execute([$k]); }
    }
    if (random_int(1, 50) === 1) {   // per-IP rows are kept for one day at most
        $pdo->prepare('DELETE FROM pswrds_limits WHERE day < ?')->execute([$day]);
        $pdo->prepare('DELETE FROM pswrds_pow_used WHERE exp < ?')->execute([time()]);
    }
}

/* ---------- Invitation codes on request ---------- */

function invite_challenge(array $cfg): void {
    $c = time() . '.' . bin2hex(random_bytes(12));
    $c .= '.' . substr(hash_hmac('sha256', 'pow:' . $c, $cfg['secret'] ?? 'change-me'), 0, 32);
    out(200, ['c' => $c, 'bits' => POW_BITS]);
}

function leading_zero_bits(string $raw): int {
    $n = 0;
    foreach (str_split($raw) as $ch) {
        $b = ord($ch);
        if ($b === 0) { $n += 8; continue; }
        while (($b & 0x80) === 0) { $n++; $b <<= 1; }
        break;
    }
    return $n;
}

function invite_request(PDO $pdo, array $cfg, array $in): void {
    $c = $in['c'] ?? null; $nonce = $in['nonce'] ?? null;
    if (!is_string($c) || !is_string($nonce) || preg_match('/^[0-9]{1,12}$/', $nonce) !== 1
        || preg_match('/^([0-9]{10})\.([0-9a-f]{24})\.([0-9a-f]{32})$/', $c, $m) !== 1) out(400, ['error' => 'bad_request']);
    $mac = substr(hash_hmac('sha256', 'pow:' . $m[1] . '.' . $m[2], $cfg['secret'] ?? 'change-me'), 0, 32);
    if (!hash_equals($mac, $m[3]) || (int)$m[1] < time() - POW_TTL || (int)$m[1] > time() + 60) out(400, ['error' => 'pow_expired']);
    if (leading_zero_bits(hash('sha256', $c . ':' . $nonce, true)) < POW_BITS) out(400, ['error' => 'pow_wrong']);
    try { $pdo->prepare('INSERT INTO pswrds_pow_used (h, exp) VALUES (?, ?)')->execute([hash('sha256', $c), (int)$m[1] + POW_TTL]); }
    catch (PDOException $e) { out(400, ['error' => 'pow_used']); }

    $ipk = ip_key($cfg, 'invite');
    if (!under_limit($pdo, $ipk, (int)($cfg['invites_per_ip'] ?? 3))) out(429, ['error' => 'invite_ip_limit']);
    if (!under_limit($pdo, 'invites-global', (int)($cfg['invites_per_day'] ?? 500))) out(429, ['error' => 'invite_day_limit']);

    $known = invite_hashes();
    for ($try = 0; $try < 20; $try++) {
        $code = new_invite_code();
        $h = hash('sha256', 'pswrds-invite:' . $code);
        if (in_array($h, $known, true)) continue;
        try { $pdo->prepare('INSERT INTO pswrds_invites_issued (h) VALUES (?)')->execute([$h]); }
        catch (PDOException $e) { continue; }   // already issued, pick another
        count_limit($pdo, $ipk);
        count_limit($pdo, 'invites-global');
        bump($pdo, 'invites_issued');
        out(200, ['code' => $code]);
    }
    out(500, ['error' => 'server_error']);
}

/** Six characters, three of them digits, in the same shape as the handed-out codes. */
function new_invite_code(): string {
    $L = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; $D = '0123456789';
    $pos = [0, 1, 2, 3, 4, 5];
    for ($i = 5; $i > 0; $i--) { $j = random_int(0, $i); [$pos[$i], $pos[$j]] = [$pos[$j], $pos[$i]]; }
    $digits = array_slice($pos, 0, 3);
    $code = '';
    for ($i = 0; $i < 6; $i++) $code .= in_array($i, $digits, true) ? $D[random_int(0, 9)] : $L[random_int(0, 25)];
    return $code;
}

function invite_valid(PDO $pdo, string $hash): bool {
    if (in_array($hash, invite_hashes(), true)) return true;
    $q = $pdo->prepare('SELECT 1 FROM pswrds_invites_issued WHERE h = ?');
    $q->execute([$hash]);
    return $q->fetchColumn() !== false;
}

/* ---------- Payments (BTCPay Server, Greenfield API) ---------- */

function btcpay(array $cfg, string $method, string $path, ?array $body = null): array {
    return http_json($method, rtrim($cfg['btcpay_url'], '/') . $path, ['Authorization: token ' . $cfg['btcpay_key']], $body, 'BTCPay');
}

function nowpayments(array $cfg, string $method, string $path, ?array $body = null): array {
    $base = $cfg['nowpayments_base'] ?? (!empty($cfg['nowpayments_sandbox']) ? 'https://api-sandbox.nowpayments.io' : 'https://api.nowpayments.io');
    return http_json($method, rtrim($base, '/') . $path, ['x-api-key: ' . $cfg['nowpayments_key']], $body, 'NOWPayments');
}

function http_json(string $method, string $url, array $headers, ?array $body, string $name): array {
    $path = (string)parse_url($url, PHP_URL_PATH);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_HTTPHEADER => array_merge($headers, ['Content-Type: application/json', 'Accept: application/json']),
    ]);
    if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_UNESCAPED_SLASHES));
    $res = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    if ($res === false || $code < 200 || $code >= 300) {
        error_log('pswrds api: ' . $name . ' ' . $method . ' ' . $path . ' failed: HTTP ' . $code . ' ' . $err . ' ' . substr((string)$res, 0, 300));
        out(502, ['error' => 'payment_provider']);
    }
    $j = json_decode((string)$res, true);
    if (!is_array($j)) out(502, ['error' => 'payment_provider']);
    return $j;
}

const LICENSE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';   // Crockford base32: no I, L, O, U

/** The license code for a settled invoice. Derived from the invoice, so it can be shown again if the page was closed. */
function license_for(array $cfg, string $invoice): string {
    $raw = hash_hmac('sha256', 'license:' . $invoice, $cfg['secret'] ?? 'change-me', true);
    $s = '';
    for ($i = 0; $i < 16; $i++) $s .= LICENSE_ALPHABET[ord($raw[$i]) & 31];
    return implode('-', str_split($s, 4));
}

function license_norm($code): ?string {
    if (!is_string($code)) return null;
    $c = strtoupper(preg_replace('/[\s-]+/', '', $code));
    $c = strtr($c, ['O' => '0', 'I' => '1', 'L' => '1']);
    return preg_match('/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{16}$/', $c) === 1 ? $c : null;
}

function license_hash(string $norm): string { return hash('sha256', 'pswrds-license:' . $norm); }

function pay_start(PDO $pdo, array $cfg): void {
    if (!payments_on($cfg)) out(503, ['error' => 'payments_off']);
    $ipk = ip_key($cfg, 'pay');
    if (!under_limit($pdo, $ipk, 20)) out(429, ['error' => 'rate_limited']);
    count_limit($pdo, $ipk);
    $order = bin2hex(random_bytes(8));   // random: says nothing about the vault
    if (provider($cfg) === 'nowpayments') {
        $inv = nowpayments($cfg, 'POST', '/v1/invoice', [
            'price_amount' => (float)($cfg['price_usd'] ?? '20'),
            'price_currency' => 'usd',
            'order_id' => $order,
            'order_description' => 'pswrds lifetime access',
            'ipn_callback_url' => ipn_url(),
        ]);
        $id = isset($inv['id']) ? (string)$inv['id'] : null; $link = $inv['invoice_url'] ?? null;
    } else {
        $inv = btcpay($cfg, 'POST', '/api/v1/stores/' . rawurlencode($cfg['btcpay_store']) . '/invoices', [
            'amount' => (string)($cfg['price_usd'] ?? '20'),
            'currency' => 'USD',
            'metadata' => ['orderId' => $order, 'itemDesc' => 'pswrds lifetime access'],
            'checkout' => ['defaultLanguage' => 'en'],
        ]);
        $id = $inv['id'] ?? null; $link = $inv['checkoutLink'] ?? null;
    }
    if (!is_string($id) || preg_match('/^[A-Za-z0-9]{3,64}$/', $id) !== 1 || !is_string($link) || stripos($link, 'https://') !== 0) {
        error_log('pswrds api: unexpected invoice response');
        out(502, ['error' => 'payment_provider']);
    }
    $claim = bin2hex(random_bytes(32));
    $pdo->prepare('INSERT INTO pswrds_orders (invoice, claim_hash, created_at, order_ref) VALUES (?, ?, ?, ?)')->execute([$id, hash('sha256', $claim), time(), $order]);
    out(200, ['invoice' => $id, 'claim' => $claim, 'link' => $link, 'amount' => (string)($cfg['price_usd'] ?? '20')]);
}

function pay_check(PDO $pdo, array $cfg, array $in): void {
    if (!payments_on($cfg)) out(503, ['error' => 'payments_off']);
    $id = $in['invoice'] ?? null; $claim = $in['claim'] ?? null;
    if (!is_string($id) || preg_match('/^[A-Za-z0-9]{3,64}$/', $id) !== 1 || !is_hex64($claim)) out(400, ['error' => 'bad_request']);
    $q = $pdo->prepare('SELECT claim_hash, status, created_at FROM pswrds_orders WHERE invoice = ?');
    $q->execute([$id]);
    $o = $q->fetch();
    if (!$o || !hash_equals($o['claim_hash'], hash('sha256', $claim))) out(404, ['error' => 'not_found']);
    if (provider($cfg) === 'nowpayments') {
        // NOWPayments reports progress by calling ipn_url(); here we only read what it reported.
        $status = (string)$o['status'];
        if ($status === 'new' && (int)$o['created_at'] < time() - 86400) $status = 'expired';   // nobody paid within a day
    } else {
        $inv = btcpay($cfg, 'GET', '/api/v1/stores/' . rawurlencode($cfg['btcpay_store']) . '/invoices/' . rawurlencode($id));
        $status = strtolower((string)($inv['status'] ?? ''));
    }
    if ($status !== 'settled') out(200, ['status' => in_array($status, ['new', 'processing', 'partial', 'expired', 'invalid'], true) ? $status : 'new']);
    $code = license_for($cfg, $id);
    try {
        $pdo->prepare('INSERT INTO pswrds_licenses (h, used) VALUES (?, 0)')->execute([license_hash(license_norm($code))]);
        bump($pdo, 'licenses_sold');
    } catch (PDOException $e) { /* already issued for this invoice */ }
    out(200, ['status' => 'settled', 'code' => $code]);
}

function redeem(PDO $pdo, array $cfg, string $id, array $in): void {
    check_token($pdo, $id, $in['token'] ?? null);
    $q = $pdo->prepare('SELECT paid FROM pswrds_vaults WHERE id = ?');
    $q->execute([$id]);
    if ((int)$q->fetchColumn() === 1) out(200, ['ok' => true, 'already' => true]);   // the code stays unused
    $norm = license_norm($in['code'] ?? null);
    if ($norm === null) out(400, ['error' => 'bad_license']);
    $pdo->beginTransaction();
    $u = $pdo->prepare('UPDATE pswrds_licenses SET used = 1 WHERE h = ? AND used = 0');
    $u->execute([license_hash($norm)]);
    if ($u->rowCount() !== 1) { $pdo->rollBack(); out(400, ['error' => 'bad_license']); }
    $pdo->prepare('UPDATE pswrds_vaults SET paid = 1 WHERE id = ?')->execute([$id]);
    $pdo->commit();
    out(200, ['ok' => true]);
}

function ipn_url(): string {
    $dir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/api.php')), '/');
    return 'https://' . ($_SERVER['HTTP_HOST'] ?? 'pswrds.com') . $dir . '/api.php?op=nowpayments_ipn';
}

/**
 * NOWPayments signs the callback body as JSON with keys sorted alphabetically (JavaScript JSON.stringify style),
 * using HMAC-SHA512 and the IPN secret. To compare exactly, the body is re-serialized here with numbers kept
 * as the very characters that were sent (PHP's json_encode would rewrite some decimals).
 */
function ipn_canonical(string $raw): ?string {
    $i = 0;
    $v = jc_value($raw, $i);
    jc_ws($raw, $i);
    return ($v === null || $i !== strlen($raw)) ? null : $v;
}
function jc_ws(string $s, int &$i): void { while ($i < strlen($s) && strpos(" \t\r\n", $s[$i]) !== false) $i++; }
function jc_value(string $s, int &$i): ?string {
    jc_ws($s, $i);
    if ($i >= strlen($s)) return null;
    $c = $s[$i];
    if ($c === '{') {
        $i++; $items = [];
        jc_ws($s, $i);
        if (($s[$i] ?? '') === '}') { $i++; return '{}'; }
        while (true) {
            jc_ws($s, $i);
            $k = jc_string($s, $i); if ($k === null) return null;
            jc_ws($s, $i); if (($s[$i] ?? '') !== ':') return null; $i++;
            $v = jc_value($s, $i); if ($v === null) return null;
            $items[$k] = $v;
            jc_ws($s, $i);
            if (($s[$i] ?? '') === ',') { $i++; continue; }
            if (($s[$i] ?? '') === '}') { $i++; break; }
            return null;
        }
        ksort($items, SORT_STRING);
        $out = [];
        foreach ($items as $k => $v) $out[] = jc_enc((string)$k) . ':' . $v;
        return '{' . implode(',', $out) . '}';
    }
    if ($c === '[') {
        $i++; $out = [];
        jc_ws($s, $i);
        if (($s[$i] ?? '') === ']') { $i++; return '[]'; }
        while (true) {
            $v = jc_value($s, $i); if ($v === null) return null;
            $out[] = $v;
            jc_ws($s, $i);
            if (($s[$i] ?? '') === ',') { $i++; continue; }
            if (($s[$i] ?? '') === ']') { $i++; break; }
            return null;
        }
        return '[' . implode(',', $out) . ']';
    }
    if ($c === '"') { $str = jc_string($s, $i); return $str === null ? null : jc_enc($str); }
    if (preg_match('/\G(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/', $s, $m, 0, $i) === 1) {
        $i += strlen($m[0]); return $m[0];
    }
    return null;
}
function jc_string(string $s, int &$i): ?string {
    if (preg_match('/\G"(?:[^"\\\\]|\\\\.)*"/s', $s, $m, 0, $i) !== 1) return null;
    $i += strlen($m[0]);
    $v = json_decode($m[0]);
    return is_string($v) ? $v : null;
}
function jc_enc(string $v): string { return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS); }

function ipn(PDO $pdo, array $cfg): void {
    if (provider($cfg) !== 'nowpayments') out(404, ['error' => 'not_found']);
    $raw = (string)file_get_contents('php://input', false, null, 0, 100_000);
    $sig = strtolower(trim((string)($_SERVER['HTTP_X_NOWPAYMENTS_SIG'] ?? '')));
    $secret = trim((string)$cfg['nowpayments_ipn_secret']);
    $canon = ipn_canonical($raw);
    $ok = $sig !== '' && $canon !== null && hash_equals(hash_hmac('sha512', $canon, $secret), $sig);
    $j = json_decode($raw, true);
    if (!$ok && is_array($j)) {   // NOWPayments' own PHP sample, as a fallback
        $sorted = $j; ksort_deep($sorted);
        $ok = $sig !== '' && hash_equals(hash_hmac('sha512', json_encode($sorted, JSON_UNESCAPED_SLASHES), $secret), $sig);
    }
    stat_set($pdo, 'ipn_last_at', time());
    stat_set($pdo, 'ipn_last_ok', $ok && is_array($j) ? 1 : 0);   // shown on the statistics page, to check the connection
    if (!$ok || !is_array($j)) { error_log('pswrds api: NOWPayments callback with a bad signature'); out(403, ['error' => 'denied']); }

    $ns = strtolower((string)($j['payment_status'] ?? ''));
    // Find our order: by invoice id, or else by the order id we sent with the invoice.
    $invoice = null; $how = 'none';
    $iid = isset($j['invoice_id']) && is_scalar($j['invoice_id']) ? (string)$j['invoice_id'] : '';
    $oid = isset($j['order_id']) && is_scalar($j['order_id']) ? (string)$j['order_id'] : '';
    if ($iid !== '') {
        $q = $pdo->prepare('SELECT invoice FROM pswrds_orders WHERE invoice = ?'); $q->execute([$iid]);
        if ($q->fetchColumn() !== false) { $invoice = $iid; $how = 'invoice'; }
    }
    if ($invoice === null && preg_match('/^[0-9a-f]{16}$/', $oid) === 1) {
        $q = $pdo->prepare('SELECT invoice FROM pswrds_orders WHERE order_ref = ?'); $q->execute([$oid]);
        $v = $q->fetchColumn();
        if ($v !== false) { $invoice = (string)$v; $how = 'order'; }
    }
    meta_set($pdo, 'ipn_last', json_encode(['status' => $ns, 'match' => $how, 'invoice_id' => $iid, 'order_id' => $oid]));
    if ($invoice === null) { error_log('pswrds api: NOWPayments callback for an unknown order: invoice ' . $iid . ', order ' . $oid); out(200); }
    $map = ['waiting' => 'new', 'confirming' => 'processing', 'partially_paid' => 'partial',
            'confirmed' => 'settled', 'sending' => 'settled', 'finished' => 'settled',
            'expired' => 'expired', 'failed' => 'invalid', 'refunded' => 'invalid'];
    $status = $map[$ns] ?? null;
    if ($status === null) out(200);
    // Wallets often deduct their network fee from the amount sent, and the rate can move while a payment confirms.
    // A payment that is short by less than (1 - pay_tolerance) still counts as paid.
    if ($status === 'partial') {
        $paid = (float)($j['actually_paid'] ?? 0); $want = (float)($j['pay_amount'] ?? 0);
        if ($want > 0 && $paid / $want >= (float)($cfg['pay_tolerance'] ?? 0.9)) $status = 'settled';
        else error_log('pswrds api: NOWPayments invoice ' . $invoice . ' partially paid: ' . $paid . ' of ' . $want . ' ' . ($j['pay_currency'] ?? ''));
    }
    if ($status === 'settled') {
        $price = (float)($cfg['price_usd'] ?? '20');
        if (strtolower((string)($j['price_currency'] ?? 'usd')) !== 'usd' || (float)($j['price_amount'] ?? 0) + 0.01 < $price) {
            error_log('pswrds api: NOWPayments invoice ' . $invoice . ' settled for an unexpected amount');
            out(200);
        }
    }
    // A settled order never goes back; anything else takes the latest report.
    $pdo->prepare("UPDATE pswrds_orders SET status = ? WHERE invoice = ? AND status <> 'settled'")->execute([$status, $invoice]);
    out(200);
}
function ksort_deep(array &$a): void { ksort($a); foreach ($a as &$v) if (is_array($v)) ksort_deep($v); }

/* ---------- Request ---------- */

$isIpn = ($_GET['op'] ?? '') === 'nowpayments_ipn' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST';
if (!$isIpn && ($_SERVER['HTTP_X_PSWRDS'] ?? '') !== '1') out(400, ['error' => 'bad_request']);

$cfg = config();
try {
    $pdo = db($cfg);
    rate_limit($pdo, $cfg['secret'] ?? 'change-me');

    if ($isIpn) ipn($pdo, $cfg);
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($method === 'GET') {
        $op = $_GET['op'] ?? '';
        if ($op === 'ping') out(200, ['ok' => true, 'v' => 2]);
        if ($op === 'invite_challenge') invite_challenge($cfg);
        if ($op !== 'vault' || !is_hex64($_GET['id'] ?? null)) out(400, ['error' => 'bad_request']);
        $id = $_GET['id'];
        $q = $pdo->prepare('SELECT iter, salt, n, paid FROM pswrds_vaults WHERE id = ?');
        $q->execute([$id]);
        $v = $q->fetch();
        if (!$v) out(404, ['error' => 'not_found']);
        $q = $pdo->prepare('SELECT i, d, v FROM pswrds_slots WHERE vault_id = ? ORDER BY i');
        $q->execute([$id]);
        $slots = array_fill(0, (int)$v['n'], null);
        $vers = array_fill(0, (int)$v['n'], 0);
        foreach ($q->fetchAll() as $r) { $slots[(int)$r['i']] = $r['d']; $vers[(int)$r['i']] = (int)$r['v']; }
        if (in_array(null, $slots, true)) out(500, ['error' => 'incomplete_vault']);
        $paid = (int)$v['paid'] === 1;
        out(200, ['header' => ['iter' => (int)$v['iter'], 'salt' => $v['salt'], 'n' => (int)$v['n']], 'slots' => $slots, 'v' => $vers,
                  'paid' => $paid, 'limit' => record_limit($cfg, $paid)]);
    }

    if ($method !== 'POST') out(405, ['error' => 'method_not_allowed']);
    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) out(415, ['error' => 'json_only']);
    $in = json_decode((string)file_get_contents('php://input', false, null, 0, 1_000_000), true);
    $op = is_array($in) ? ($in['op'] ?? '') : '';
    if ($op === 'stats') stats($pdo, $cfg, $in['pass'] ?? null);
    if ($op === 'admin_license') admin_license($pdo, $cfg, $in['pass'] ?? null);
    if ($op === 'invite_request') invite_request($pdo, $cfg, $in);
    if ($op === 'pay_start') pay_start($pdo, $cfg);
    if ($op === 'pay_check') pay_check($pdo, $cfg, $in);
    if (!is_array($in) || !is_hex64($in['id'] ?? null)) out(400, ['error' => 'bad_request']);
    $id = $in['id'];

    switch ($in['op'] ?? '') {
        case 'create':
            $h = $in['header'] ?? null;
            $slots = $in['slots'] ?? null;
            if (!is_hex64($in['token'] ?? null)
                || !is_array($h) || !is_int($h['iter'] ?? null) || $h['iter'] < 100000 || $h['iter'] > 10000000
                || !is_string($h['salt'] ?? null) || strlen(base64_decode($h['salt'], true) ?: '') !== 16
                || ($h['n'] ?? null) !== NSLOTS
                || !is_array($slots) || count($slots) !== NSLOTS || !array_is_list($slots)) {
                out(400, ['error' => 'bad_request']);
            }
            foreach ($slots as $d) if (!is_slot($d)) out(400, ['error' => 'bad_slot']);
            $inviteHash = null;
            if (array_key_exists('invite', $in)) {
                $code = $in['invite'];
                if (!is_string($code) || preg_match('/^[A-Z0-9]{6}$/', $code) !== 1) out(400, ['error' => 'bad_invite']);
                $inviteHash = hash('sha256', 'pswrds-invite:' . $code);
                if (!invite_valid($pdo, $inviteHash)) out(400, ['error' => 'bad_invite']);
            }
            $pdo->beginTransaction();
            try {
                $pdo->prepare('INSERT INTO pswrds_vaults (id, token_hash, iter, salt, n, created_at) VALUES (?, ?, ?, ?, ?, ?)')
                    ->execute([$id, hash('sha256', $in['token']), $h['iter'], $h['salt'], NSLOTS, time()]);
            } catch (PDOException $e) {
                $pdo->rollBack();
                out(409, ['error' => 'taken']);
            }
            if ($inviteHash !== null) {
                try {
                    $pdo->prepare('INSERT INTO pswrds_invites_used (h) VALUES (?)')->execute([$inviteHash]);
                } catch (PDOException $e) {
                    $pdo->rollBack();   // code already used: nothing is created
                    out(400, ['error' => 'bad_invite']);
                }
            }
            $ins = $pdo->prepare('INSERT INTO pswrds_slots (vault_id, i, d, v) VALUES (?, ?, ?, ?)');
            $vers = [];
            foreach ($slots as $i => $d) { $vers[$i] = new_ver(); $ins->execute([$id, $i, $d, $vers[$i]]); }
            bump($pdo, $inviteHash !== null ? 'created_invited' : 'created_plain');
            $pdo->commit();
            out(201, ['ok' => true, 'paid' => false, 'limit' => record_limit($cfg, false), 'v' => $vers]);

        case 'slot':
            $i = $in['i'] ?? null;
            if (!is_int($i) || $i < 0 || $i >= NSLOTS || !is_slot($in['d'] ?? null)) out(400, ['error' => 'bad_request']);
            $ver = $in['v'] ?? null;
            if ($ver !== null && !is_int($ver)) out(400, ['error' => 'bad_request']);
            check_token($pdo, $id, $in['token'] ?? null);
            $nv = new_ver();
            if ($ver === null) {   // older app: no version check
                $pdo->prepare('UPDATE pswrds_slots SET d = ?, v = ? WHERE vault_id = ? AND i = ?')->execute([$in['d'], $nv, $id, $i]);
            } else {
                $u = $pdo->prepare('UPDATE pswrds_slots SET d = ?, v = ? WHERE vault_id = ? AND i = ? AND v = ?');
                $u->execute([$in['d'], $nv, $id, $i, $ver]);
                if ($u->rowCount() !== 1) out(409, ['error' => 'stale']);   // changed meanwhile on another device
            }
            out(200, ['ok' => true, 'v' => $nv]);

        case 'slots':   // several slots at once, optionally with a new write token, all or nothing
            $sl = $in['slots'] ?? null;
            if (!is_array($sl) || count($sl) < 1 || count($sl) > NSLOTS) out(400, ['error' => 'bad_request']);
            $new = $in['new_token'] ?? null;
            if ($new !== null && !is_hex64($new)) out(400, ['error' => 'bad_request']);
            $vers = $in['vers'] ?? null;
            if ($vers !== null && !is_array($vers)) out(400, ['error' => 'bad_request']);
            $rows = [];
            foreach ($sl as $k => $d) {
                if (!is_int($k) && !(is_string($k) && ctype_digit($k))) out(400, ['error' => 'bad_request']);
                $i = (int)$k;
                if ($i < 0 || $i >= NSLOTS || !is_slot($d)) out(400, ['error' => 'bad_request']);
                $rows[$i] = $d;
            }
            check_token($pdo, $id, $in['token'] ?? null);
            $pdo->beginTransaction();
            $u = $pdo->prepare('UPDATE pswrds_slots SET d = ?, v = ? WHERE vault_id = ? AND i = ?');
            $uv = $pdo->prepare('UPDATE pswrds_slots SET d = ?, v = ? WHERE vault_id = ? AND i = ? AND v = ?');
            foreach ($rows as $i => $d) {
                $ver = is_array($vers) ? ($vers[(string)$i] ?? $vers[$i] ?? null) : null;
                if ($ver === null) { $u->execute([$d, new_ver(), $id, $i]); continue; }
                if (!is_int($ver)) { $pdo->rollBack(); out(400, ['error' => 'bad_request']); }
                $uv->execute([$d, new_ver(), $id, $i, $ver]);
                if ($uv->rowCount() !== 1) { $pdo->rollBack(); out(409, ['error' => 'stale']); }
            }
            if ($new !== null) $pdo->prepare('UPDATE pswrds_vaults SET token_hash = ? WHERE id = ?')->execute([hash('sha256', $new), $id]);
            $pdo->commit();
            $out = [];
            foreach (array_keys($rows) as $i) $out[(string)$i] = slot_version($pdo, $id, $i);
            out(200, ['ok' => true, 'vers' => $out]);

        case 'redeem':
            redeem($pdo, $cfg, $id, $in);

        case 'delete':
            check_token($pdo, $id, $in['token'] ?? null);
            $pdo->beginTransaction();
            $pdo->prepare('DELETE FROM pswrds_slots WHERE vault_id = ?')->execute([$id]);
            $pdo->prepare('DELETE FROM pswrds_vaults WHERE id = ?')->execute([$id]);
            bump($pdo, 'deleted');
            $pdo->commit();
            out(200);

        default:
            out(400, ['error' => 'bad_request']);
    }
} catch (Throwable $e) {
    error_log('pswrds api: ' . $e->getMessage());
    out(500, ['error' => 'server_error']);
}
