<?php
// iscrip-adm-2025.php
// Painel administrativo (skeleton) atualizado 2025
// Single-file example: PDO + CSRF + RBAC + API Tokens + Audit log + Dark mode + rate limiting
// Segurança: use HTTPS, coloque credenciais em variáveis de ambiente, desative display_errors em produção.

declare(strict_types=1);
session_start();

// ---------- CONFIG ----------
$dbDsn = getenv('DB_DSN') ?: 'sqlite:' . __DIR__ . '/iscrip-adm.db'; // exemplo: mysql:host=...;dbname=...
$dbUser = getenv('DB_USER') ?: null;
$dbPass = getenv('DB_PASS') ?: null;
$appName = 'iScrip ADM 2025';

// ---------- DB CONNECTION ----------
try {
    $pdo = new PDO($dbDsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (Exception $e) {
    http_response_code(500);
    echo "DB error: " . htmlspecialchars($e->getMessage());
    exit;
}

// ---------- SIMPLE MIGRATION (executar 1x) ----------
function migrate(PDO $pdo) {
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'editor',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );");

    $pdo->exec("CREATE TABLE IF NOT EXISTS api_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT UNIQUE,
        name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );");

    $pdo->exec("CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        ip TEXT,
        meta TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );");

    // Create default admin user if none
    $stmt = $pdo->query("SELECT COUNT(*) as c FROM users");
    $c = $stmt->fetchColumn();
    if ($c == 0) {
        $pw = password_hash('admin123', PASSWORD_ARGON2ID);
        $pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")
            ->execute(['admin', $pw, 'admin']);
    }
}

migrate($pdo);

// ---------- UTILITIES ----------
function ip() {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function csrf_token() {
    if (empty($_SESSION['_csrf'])) $_SESSION['_csrf'] = bin2hex(random_bytes(24));
    return $_SESSION['_csrf'];
}

function verify_csrf($token) {
    return hash_equals($_SESSION['_csrf'] ?? '', $token ?? '');
}

function require_auth() {
    if (empty($_SESSION['user'])) {
        header('Location: ?action=login');
        exit;
    }
}

function current_user(PDO $pdo) {
    if (empty($_SESSION['user_id'])) return null;
    $stmt = $pdo->prepare('SELECT id,username,role FROM users WHERE id=?');
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetch();
}

function audit(PDO $pdo, $userId, $action, $meta = null) {
    $stmt = $pdo->prepare('INSERT INTO audit_log (user_id,action,ip,meta) VALUES (?,?,?,?)');
    $stmt->execute([$userId, $action, ip(), json_encode($meta)]);
}

// Very small rate limiter per session (example)
function rate_limit_check($key, $limit = 10, $seconds = 60) {
    if (!isset($_SESSION['_rl'])) $_SESSION['_rl'] = [];
    $now = time();
    $_SESSION['_rl'][$key] = array_filter($_SESSION['_rl'][$key] ?? [], function($t) use ($now, $seconds) { return $t + $seconds > $now; });
    if (count($_SESSION['_rl'][$key]) >= $limit) return false;
    $_SESSION['_rl'][$key][] = $now;
    return true;
}

// ---------- AUTH HANDLERS ----------
$action = $_GET['action'] ?? 'dashboard';

if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!rate_limit_check('login', 8, 60)) { die('Too many attempts. Try later.'); }
    if (!verify_csrf($_POST['_csrf'] ?? '')) { die('CSRF token inválido'); }
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $stmt = $pdo->prepare('SELECT * FROM users WHERE username=?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    if ($user && password_verify($password, $user['password'])) {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user'] = $user['username'];
        audit($pdo, $user['id'], 'login', ['ua'=>$_SERVER['HTTP_USER_AGENT'] ?? '']);
        header('Location: ?action=dashboard');
        exit;
    } else {
        audit($pdo, $user['id'] ?? null, 'login_failed', ['username'=>$username]);
        $err = 'Credenciais inválidas';
    }
}

if ($action === 'logout') {
    audit($pdo, $_SESSION['user_id'] ?? null, 'logout');
    session_unset(); session_destroy();
    header('Location: ?action=login'); exit;
}

// ---------- API token creation (example) ----------
if ($action === 'create_api_token' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    require_auth();
    if (!verify_csrf($_POST['_csrf'] ?? '')) { die('CSRF token inválido'); }
    $user = current_user($pdo);
    $name = substr($_POST['name'] ?? 'token',0,64);
    $token = bin2hex(random_bytes(32));
    $pdo->prepare('INSERT INTO api_tokens (user_id,token,name) VALUES (?,?,?)')
        ->execute([$user['id'],$token,$name]);
    audit($pdo, $user['id'], 'create_api_token', ['name'=>$name]);
    // show token once
    $_SESSION['_new_token'] = $token;
    header('Location: ?action=api_tokens'); exit;
}

// ---------- Routing helpers ----------
ob_start();
?><!doctype html>

<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title><?=htmlspecialchars($appName)?> — Painel</title>
    <style>
        :root{--bg:#f3f4f6;--card:#fff;--text:#111}
        [data-theme="dark"]{--bg:#0b1220;--card:#071026;--text:#e6eef8}
        body{font-family:Inter,system-ui,Segoe UI,Roboto,Arial;margin:0;background:var(--bg);color:var(--text)}
        .wrap{max-width:1100px;margin:24px auto;padding:16px}
        .card{background:var(--card);padding:16px;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,0.08)}
        .top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}
        nav a{margin-right:12px}
        table{width:100%;border-collapse:collapse}
        th,td{padding:8px;border-bottom:1px solid rgba(0,0,0,0.06)}
        .danger{color:#b00020}
        .small{font-size:0.85rem;color:gray}
        .btn{padding:8px 12px;border-radius:8px;border:0;background:#2563eb;color:#fff;cursor:pointer}
    </style>
</head>
<body data-theme="light">
<div class="wrap">
    <div class="top">
        <div>
            <strong><?=htmlspecialchars($appName)?></strong>
            <span class="small">— painel administrativo</span>
        </div>
        <div>
            <button id="theme-toggle" class="btn">Dark</button>
            <?php if (!empty($_SESSION['user'])): ?>
                <a href="?action=logout" class="btn">Sair</a>
            <?php endif; ?>
        </div>
    </div><?php if (empty($_SESSION['user'])): ?>
    <div class="card">
        <h2>Login</h2>
        <?php if (!empty($err)): ?><div class="danger"><?php echo htmlspecialchars($err);?></div><?php endif; ?>
        <form method="POST" action="?action=login">
            <input type="hidden" name="_csrf" value="<?=csrf_token()?>">
            <div><label>Usuário<br><input name="username"></label></div>
            <div><label>Senha<br><input type="password" name="password"></label></div>
            <div style="margin-top:8px"><button class="btn">Entrar</button></div>
        </form>
        <p class="small">Usuário padrão: <code>admin</code> / Senha: <code>admin123</code> (trocar)</p>
    </div>
<?php else: ?>
    <?php $user = current_user($pdo); ?>
    <nav class="small card" style="margin-bottom:12px">
        <a href="?action=dashboard">Dashboard</a>
        <a href="?action=users">Usuários</a>
        <a href="?action=api_tokens">API Tokens</a>
        <a href="?action=audit_log">Audit Log</a>
        <a href="?action=settings">Configurações</a>
    </nav>

    <?php if ($action === 'dashboard'): ?>
        <div class="card">
            <h2>Dashboard</h2>
            <p>Bem vindo, <?=htmlspecialchars($user['username'])?> — função: <?=htmlspecialchars($user['role'])?></p>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:12px">
                <div class="card"><strong>Usuários</strong>
                    <?php $c = $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn(); ?><div class="small"><?= $c ?> cadastrados</div>
                </div>
                <div class="card"><strong>Tokens</strong>
                    <?php $c2 = $pdo->query('SELECT COUNT(*) FROM api_tokens')->fetchColumn(); ?><div class="small"><?= $c2 ?> tokens</div>
                </div>
            </div>
        </div>

    <?php elseif ($action === 'users'): ?>
        <div class="card">
            <h2>Gerenciar Usuários</h2>
            <?php
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_user'])) {
                if (!verify_csrf($_POST['_csrf'] ?? '')) die('CSRF');
                $u = substr($_POST['username'],0,64);
                $pw = password_hash($_POST['password'], PASSWORD_ARGON2ID);
                $role = in_array($_POST['role'],['admin','editor','viewer']) ? $_POST['role'] : 'editor';
                $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$u,$pw,$role]);
                audit($pdo, $user['id'], 'create_user', ['username'=>$u]);
                echo '<div class="small">Usuário criado.</div>';
            }
            ?>
            <form method="POST">
                <input type="hidden" name="_csrf" value="<?=csrf_token()?>">
                <input type="hidden" name="create_user" value="1">
                <div><label>Usuário <input name="username"></label></div>
                <div><label>Senha <input name="password" type="password"></label></div>
                <div><label>Função <select name="role"><option>editor</option><option>admin</option><option>viewer</option></select></label></div>
                <div style="margin-top:8px"><button class="btn">Criar</button></div>
            </form>
            <hr>
            <h3>Lista</h3>
            <table>
                <thead><tr><th>ID</th><th>Usuário</th><th>Função</th><th>Criado</th></tr></thead>
                <tbody>
                    <?php foreach ($pdo->query('SELECT id,username,role,created_at FROM users ORDER BY id DESC') as $row): ?>
                        <tr><td><?= $row['id']?></td><td><?=htmlspecialchars($row['username'])?></td><td><?=htmlspecialchars($row['role'])?></td><td><?=htmlspecialchars($row['created_at'])?></td></tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

    <?php elseif ($action === 'api_tokens'): ?>
        <div class="card">
            <h2>API Tokens</h2>
            <?php if (!empty($_SESSION['_new_token'])): $t = $_SESSION['_new_token']; unset($_SESSION['_new_token']); ?>
                <div class="card">Token (guarde agora, será mostrado uma vez): <code><?=htmlspecialchars($t)?></code></div>
            <?php endif; ?>
            <form method="POST" action="?action=create_api_token">
                <input type="hidden" name="_csrf" value="<?=csrf_token()?>">
                <label>Nome do token <input name="name"></label>
                <div style="margin-top:8px"><button class="btn">Gerar token</button></div>
            </form>
            <hr>
            <h3>Ativos</h3>
            <table>
                <thead><tr><th>ID</th><th>Nome</th><th>Criado</th></tr></thead>
                <tbody>
                    <?php $stmt = $pdo->prepare('SELECT id,name,created_at FROM api_tokens WHERE user_id=? ORDER BY id DESC'); $stmt->execute([$user['id']]);
                    while($r = $stmt->fetch()): ?>
                        <tr><td><?=$r['id']?></td><td><?=htmlspecialchars($r['name'])?></td><td><?=htmlspecialchars($r['created_at'])?></td></tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>

    <?php elseif ($action === 'audit_log'): ?>
        <div class="card">
            <h2>Audit Log</h2>
            <table>
                <thead><tr><th>ID</th><th>User</th><th>Ação</th><th>IP</th><th>Quando</th></tr></thead>
                <tbody>
                    <?php $stmt = $pdo->query('SELECT a.id,a.action,a.ip,a.created_at,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200');
                    foreach($stmt as $r): ?>
                        <tr><td><?=$r['id']?></td><td><?=htmlspecialchars($r['username'] ?? '—')?></td><td><?=htmlspecialchars($r['action'])?></td><td><?=htmlspecialchars($r['ip'])?></td><td><?=htmlspecialchars($r['created_at'])?></td></tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

    <?php elseif ($action === 'settings'): ?>
        <div class="card">
            <h2>Configurações</h2>
            <p class="small">Exemplos: habilitar OAuth, configurar storage, ativar 2FA, integrações.</p>
            <div class="card">
                <strong>Recomendações de 2025</strong>
                <ul class="small">
                    <li>Forçar HTTPS/HSTS</li>
                    <li>Implementar autenticação de segundo fator (U2F/TOTP)</li>
                    <li>Usar password hashing moderno (Argon2id)</li>
                    <li>Limiter por IP / WAF e monitoração</li>
                    <li>Rotacionar e armazenar segredos em serviço de vault</li>
                </ul>
            </div>
        </div>
    <?php endif; ?>
<?php endif; ?>

<footer class="small" style="margin-top:12px;text-align:center">iscrip-adm • atualizado 2025</footer>

</div><script>
// Theme toggle (persist in localStorage)
const root = document.documentElement;
const btn = document.getElementById('theme-toggle');
function setTheme(t){ document.body.setAttribute('data-theme', t); localStorage.setItem('theme', t); btn.textContent = t === 'dark' ? 'Light' : 'Dark'; }
const saved = localStorage.getItem('theme') || 'light'; setTheme(saved);
btn.addEventListener('click', ()=> setTheme(document.body.getAttribute('data-theme') === 'light' ? 'dark' : 'light'));

// Attach CSRF token to fetch requests automatically
const csrf = '<?=csrf_token()?>';
(function(){
    const _fetch = window.fetch;
    window.fetch = function(url, opts={}){
        opts.headers = opts.headers || {};
        if (['POST','PUT','DELETE','PATCH'].includes((opts.method||'GET').toUpperCase())) {
            if (opts.headers instanceof Headers) opts.headers.set('X-CSRF-Token', csrf);
            else opts.headers['X-CSRF-Token'] = csrf;
        }
        return _fetch(url, opts);
    };
})();
</script></body>
</html>
<?php
// Flush
echo ob_get_clean();
