#!/usr/bin/env bash
#
# deploy-soc-dash.sh
# Full deployment for https://github.com/SleepTheGod/SOC-Dash
#
# Repo entry points: index.php  (primary), index.html (fallback/static)
#
# Usage:  sudo bash deploy-soc-dash.sh
#
set -Eeuo pipefail

# ================================================================
# CONFIG — edit these if you need to
# ================================================================
REPO_URL="https://github.com/SleepTheGod/SOC-Dash.git"
REPO_BRANCH="main"

APP_DIR="/var/www/soc-dash"
APP_USER="www-data"          # PHP-FPM user (Apache: www-data / apache)
SERVER_NAME="soc.internal"   # vhost server_name
WEB_SERVER="nginx"           # nginx | apache

# Entry points — the repo ships both. index.php takes priority.
ENTRY_PRIMARY="index.php"
ENTRY_FALLBACK="index.html"

# Database — set to auto-detect schema in the repo
NEEDS_DB="auto"              # auto | no | mysql | postgres | sqlite
DB_NAME="soc_dash"
DB_USER="soc"
DB_PASS=""                   # leave empty → auto-generated

# Cron (history collector / cleanup, only if repo provides cron.php)
NEEDS_CRON="auto"            # auto | no | yes
CRON_SCHEDULE="*/5 * * * *"

# Network allowlist (defense-in-depth — restricts the vhost)
ALLOWED_CIDRS=("127.0.0.1/32" "10.0.0.0/8" "192.168.0.0/16" "172.16.0.0/12")

# Optional app token written into a generated config (leave empty to skip)
APP_TOKEN=""

# ================================================================
# Colors / logging
# ================================================================
RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; CYN=$'\e[36m'; BLD=$'\e[1m'; RST=$'\e[0m'
log()  { printf '%s[*]%s %s\n' "$CYN" "$RST" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YLW" "$RST" "$*"; }
die()  { printf '%s[x]%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
step() { printf '\n%s==> %s%s\n' "$BLD" "$*" "$RST"; }

# ================================================================
# Pre-flight
# ================================================================
[[ $EUID -eq 0 ]] || die "Run as root (sudo bash $0)"

if   command -v apt-get >/dev/null; then DISTRO=debian
elif command -v dnf     >/dev/null; then DISTRO=rhel
elif command -v yum     >/dev/null; then DISTRO=rhel
elif command -v pacman  >/dev/null; then DISTRO=arch
else die "Unsupported distro (no apt/dnf/yum/pacman)"
fi
ok "Detected distro family: $DISTRO"

# ================================================================
# STEP 1 — Base packages
# ================================================================
step "Installing base packages"
case "$DISTRO" in
  debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        git curl ca-certificates unzip \
        php-cli php-fpm php-mbstring php-curl php-xml php-zip php-json \
        iproute2 procps psmisc net-tools
    ;;
  rhel)
    dnf install -y -q \
        git curl ca-certificates unzip \
        php-cli php-fpm php-mbstring php-curl php-xml php-zip php-json \
        iproute procps-ng psmisc net-tools
    ;;
  arch)
    pacman -Sy --noconfirm --quiet git curl unzip \
        php php-fpm php-sqlite iproute2 procps-ng psmisc net-tools
    ;;
esac
ok "Base packages installed"

# ================================================================
# STEP 2 — Clone / update the repo
# ================================================================
step "Fetching repository"
if [[ -d "$APP_DIR/.git" ]]; then
    log "Existing checkout found — pulling latest"
    git -C "$APP_DIR" fetch --all --quiet
    git -C "$APP_DIR" reset --hard "origin/${REPO_BRANCH}" --quiet
else
    log "Cloning $REPO_URL (branch $REPO_BRANCH)"
    mkdir -p "$(dirname "$APP_DIR")"
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$APP_DIR"
fi

# Sanity: at least one entry point must exist
[[ -f "$APP_DIR/$ENTRY_PRIMARY" || -f "$APP_DIR/$ENTRY_FALLBACK" ]] \
    || die "Neither $ENTRY_PRIMARY nor $ENTRY_FALLBACK found in $APP_DIR"

FOUND=""
[[ -f "$APP_DIR/$ENTRY_PRIMARY"  ]] && FOUND+="$ENTRY_PRIMARY "
[[ -f "$APP_DIR/$ENTRY_FALLBACK" ]] && FOUND+="$ENTRY_FALLBACK "
ok "Entry points present: $FOUND"

# ================================================================
# STEP 3 — Detect DB requirement
# ================================================================
step "Detecting database requirement"

SCHEMA_FILE=""
for cand in schema.sql install.sql database.sql db.sql init.sql setup.sql; do
    if [[ -f "$APP_DIR/$cand" ]]; then SCHEMA_FILE="$APP_DIR/$cand"; break; fi
done
if [[ -z "$SCHEMA_FILE" ]]; then
    # Look one level deep
    SCHEMA_FILE="$(find "$APP_DIR" -maxdepth 2 -type f -name '*.sql' 2>/dev/null | head -n1 || true)"
fi

DETECTED_DB="no"
if grep -rIl --exclude-dir=.git -E 'mysqli|PDO.*mysql|pg_connect|PDO.*pgsql' "$APP_DIR" >/dev/null 2>&1; then
    if grep -rIl --exclude-dir=.git -E 'pgsql|pg_connect' "$APP_DIR" >/dev/null 2>&1; then
        DETECTED_DB="postgres"
    else
        DETECTED_DB="mysql"
    fi
elif grep -rIl --exclude-dir=.git -E 'sqlite|PDO.*sqlite' "$APP_DIR" >/dev/null 2>&1; then
    DETECTED_DB="sqlite"
fi

if [[ "$NEEDS_DB" == "auto" ]]; then NEEDS_DB="$DETECTED_DB"; fi
[[ -n "$SCHEMA_FILE" && "$NEEDS_DB" == "no" ]] && NEEDS_DB="mysql"

ok "Database mode: $NEEDS_DB${SCHEMA_FILE:+  (schema: $SCHEMA_FILE)}"

# Generate a DB password if not supplied
if [[ "$NEEDS_DB" != "no" && "$NEEDS_DB" != "sqlite" && -z "$DB_PASS" ]]; then
    if command -v openssl >/dev/null; then
        DB_PASS="$(openssl rand -hex 16)"
    else
        DB_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
    fi
    ok "Generated DB password (save this!): $DB_PASS"
fi

# ================================================================
# STEP 4 — Install DB stack if needed
# ================================================================
case "$NEEDS_DB" in
  mysql)
    step "Installing MariaDB"
    case "$DISTRO" in
      debian) apt-get install -y -qq php-mysql mariadb-server ;;
      rhel)   dnf install -y -q php-mysqlnd mariadb-server ;;
      arch)   pacman -S --noconfirm --quiet mariadb php-mysql ;;
    esac
    systemctl enable --now mariadb 2>/dev/null || systemctl enable --now mysql
    # Wait for socket
    for i in {1..20}; do
        mysqladmin ping >/dev/null 2>&1 && break
        sleep 0.5
    done
    log "Creating database $DB_NAME and user $DB_USER"
    mysql -e "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
    mysql -e "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    if [[ -n "$SCHEMA_FILE" ]]; then
        log "Importing schema: $SCHEMA_FILE"
        mysql "$DB_NAME" < "$SCHEMA_FILE" && ok "Schema imported" || warn "Schema import failed — import manually"
    fi
    ok "MariaDB ready"
    ;;
  postgres)
    step "Installing PostgreSQL"
    case "$DISTRO" in
      debian) apt-get install -y -qq php-pgsql postgresql ;;
      rhel)   dnf install -y -q php-pgsql postgresql-server postgresql-contrib
              postgresql-setup --initdb || true ;;
      arch)   pacman -S --noconfirm --quiet postgresql php-pgsql
              sudo -u postgres initdb -D /var/lib/postgres/data 2>/dev/null || true ;;
    esac
    systemctl enable --now postgresql
    sleep 2
    sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';"
    sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 || \
        sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}"
    if [[ -n "$SCHEMA_FILE" ]]; then
        log "Importing schema: $SCHEMA_FILE"
        sudo -u postgres psql "${DB_NAME}" < "$SCHEMA_FILE" && ok "Schema imported" || warn "Schema import failed"
    fi
    ok "PostgreSQL ready"
    ;;
  sqlite)
    step "Preparing SQLite"
    mkdir -p "$APP_DIR/data"
    chown "$APP_USER":"$APP_USER" "$APP_DIR/data"
    chmod 750 "$APP_DIR/data"
    if [[ -n "$SCHEMA_FILE" ]] && command -v sqlite3 >/dev/null; then
        sqlite3 "$APP_DIR/data/soc.db" < "$SCHEMA_FILE" && ok "SQLite schema imported"
    fi
    ok "SQLite ready at $APP_DIR/data/soc.db"
    ;;
  no)
    ok "No database required"
    ;;
esac

# ================================================================
# STEP 5 — Generate config if the app expects one
# ================================================================
step "Checking for config templates"
CONFIG_WRITTEN=""
for tpl in config.sample.php config.example.php config.dist.php .env.example .env.sample; do
    if [[ -f "$APP_DIR/$tpl" ]]; then
        target="${tpl/sample/}"; target="${target/example/}"; target="${target/dist/}"
        target="${target/.example/}"; target="${target/.sample/}"
        if [[ ! -f "$APP_DIR/$target" ]]; then
            cp "$APP_DIR/$tpl" "$APP_DIR/$target"
            CONFIG_WRITTEN="$target"
            ok "Created $target from $tpl"
        fi
    fi
done

if [[ -n "$CONFIG_WRITTEN" ]]; then
    if [[ "$NEEDS_DB" == "mysql" || "$NEEDS_DB" == "postgres" ]]; then
        sed -i "s|DB_NAME_PLACEHOLDER|${DB_NAME}|g; \
                s|DB_USER_PLACEHOLDER|${DB_USER}|g; \
                s|DB_PASS_PLACEHOLDER|${DB_PASS}|g" "$APP_DIR/$CONFIG_WRITTEN" || true
    fi
    if [[ -n "$APP_TOKEN" ]]; then
        sed -i "s|TOKEN_PLACEHOLDER|${APP_TOKEN}|g" "$APP_DIR/$CONFIG_WRITTEN" || true
    fi
fi

# ================================================================
# STEP 6 — Permissions
# ================================================================
step "Setting permissions"
chown -R "$APP_USER":"$APP_USER" "$APP_DIR"
find "$APP_DIR" -type d -exec chmod 750 {} \;
find "$APP_DIR" -type f -exec chmod 640 {} \;
[[ -f "$APP_DIR/$ENTRY_PRIMARY"  ]] && chmod 644 "$APP_DIR/$ENTRY_PRIMARY"
[[ -f "$APP_DIR/$ENTRY_FALLBACK" ]] && chmod 644 "$APP_DIR/$ENTRY_FALLBACK"
# Keep git dir private
[[ -d "$APP_DIR/.git" ]] && chmod -R 700 "$APP_DIR/.git"
ok "Permissions set (dir 750, files 640, entry 644)"

# ================================================================
# STEP 7 — PHP-FPM tuning (enable shell_exec, join log groups)
# ================================================================
step "Tuning PHP-FPM"

case "$DISTRO" in
  debian) FPM_INI_GLOB="/etc/php/*/fpm/php.ini" ;;
  rhel)   FPM_INI_GLOB="/etc/php.ini" ;;
  arch)   FPM_INI_GLOB="/etc/php/php.ini" ;;
esac

for f in $FPM_INI_GLOB; do
    [[ -f "$f" ]] || continue
    if grep -qE '^\s*disable_functions\s*=' "$f"; then
        # Preserve list but remove shell_exec from it
        sed -i -E 's/\bshell_exec\s*,?\s*//g; s/,\s*,/,/g; s/^\s*disable_functions\s*=\s*,/disable_functions =/' "$f"
    fi
    # Raise a couple of limits for the dashboard
    sed -i -E 's/^\s*max_execution_time\s*=.*/max_execution_time = 30/' "$f" || true
    sed -i -E 's/^\s*memory_limit\s*=.*/memory_limit = 256M/' "$f" || true
done
ok "PHP-FPM ini tuned"

# Group memberships for log reading
if [[ "$DISTRO" == "debian" ]]; then
    usermod -aG systemd-journal "$APP_USER" 2>/dev/null || true
    usermod -aG adm             "$APP_USER" 2>/dev/null || true
elif [[ "$DISTRO" == "rhel" ]]; then
    usermod -aG systemd-journal "$APP_USER" 2>/dev/null || true
    usermod -aG wheel           "$APP_USER" 2>/dev/null || true
fi
[[ -f /var/log/auth.log ]] && chmod 640 /var/log/auth.log && chgrp adm   /var/log/auth.log 2>/dev/null || true
[[ -f /var/log/secure   ]] && chmod 640 /var/log/secure   && chgrp wheel /var/log/secure   2>/dev/null || true

# Restart PHP-FPM (handle both php-fpm and phpX.Y-fpm service names)
if systemctl list-unit-files | grep -qE '^php[0-9.]+-fpm\.service'; then
    systemctl restart "$(systemctl list-unit-files | grep -oE '^php[0-9.]+-fpm\.service' | head -n1)"
else
    systemctl restart php-fpm 2>/dev/null || true
fi
ok "PHP-FPM restarted"

# ================================================================
# STEP 8 — Web server
# ================================================================
step "Configuring $WEB_SERVER"

# Detect PHP-FPM socket
PHP_VER="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo '')"
if [[ "$DISTRO" == "debian" ]]; then
    PHP_SOCK="unix:/run/php/php${PHP_VER}-fpm.sock"
elif [[ "$DISTRO" == "rhel" ]]; then
    PHP_SOCK="unix:/run/php-fpm/www.sock"
else
    PHP_SOCK="unix:/run/php-fpm/php-fpm.sock"
fi

# Build allow/deny fragments
NGINX_ALLOW=""
for cidr in "${ALLOWED_CIDRS[@]}"; do NGINX_ALLOW+="    allow ${cidr};"$'\n'; done
NGINX_ALLOW+="    deny all;"$'\n'

APACHE_ALLOW=""
for cidr in "${ALLOWED_CIDRS[@]}"; do APACHE_ALLOW+="        Require ip ${cidr}"$'\n'; done

if [[ "$WEB_SERVER" == "nginx" ]]; then
    case "$DISTRO" in
      debian) apt-get install -y -qq nginx ;;
      rhel)   dnf install -y -q nginx ;;
      arch)   pacman -S --noconfirm --quiet nginx ;;
    esac

    if [[ "$DISTRO" == "debian" ]]; then
        SITE="/etc/nginx/sites-available/soc-dash"
        ENABLED="/etc/nginx/sites-enabled/soc-dash"
    else
        SITE="/etc/nginx/conf.d/soc-dash.conf"
        ENABLED="$SITE"
    fi

    cat > "$SITE" <<EOF
server {
    listen 80;
    server_name ${SERVER_NAME};

    root ${APP_DIR};
    index ${ENTRY_PRIMARY} ${ENTRY_FALLBACK};

    ${NGINX_ALLOW}
    location / {
        try_files \$uri \$uri/ /${ENTRY_PRIMARY}?\$query_string;
    }

    location ~ \.php\$ {
        include fastcgi_params;
        fastcgi_pass ${PHP_SOCK};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_read_timeout 30s;
    }

    # Block sensitive paths
    location ~ /\.(git|env)         { deny all; }
    location ~* \.(sql|log|conf|sh)\$ { deny all; }
    location ~ /(data|vendor)/       { deny all; }

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header Referrer-Policy no-referrer;
}
EOF

    if [[ "$DISTRO" == "debian" ]]; then ln -sf "$SITE" "$ENABLED"; fi
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
    ok "Nginx vhost live"

elif [[ "$WEB_SERVER" == "apache" ]]; then
    case "$DISTRO" in
      debian)
        apt-get install -y -qq apache2 libapache2-mod-php
        a2enmod rewrite headers proxy proxy_fcgi setenvif >/dev/null
        a2dissite 000-default >/dev/null 2>&1 || true
        SITE="/etc/apache2/sites-available/soc-dash.conf"
        ;;
      rhel)
        dnf install -y -q httpd php
        SITE="/etc/httpd/conf.d/soc-dash.conf"
        ;;
      arch)
        pacman -S --noconfirm --quiet apache php-apache
        SITE="/etc/httpd/conf/extra/soc-dash.conf"
        ;;
    esac

    cat > "$SITE" <<EOF
<VirtualHost *:80>
    ServerName ${SERVER_NAME}
    DocumentRoot ${APP_DIR}

    <Directory ${APP_DIR}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all denied
${APACHE_ALLOW}    </Directory>

    # Block sensitive paths
    <LocationMatch "/\.(git|env)">
        Require all denied
    </LocationMatch>
    <FilesMatch "\.(sql|log|conf|sh)\$">
        Require all denied
    </FilesMatch>

    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    Header always set Referrer-Policy no-referrer

    ErrorLog  \${APACHE_LOG_DIR}/soc-error.log
    CustomLog \${APACHE_LOG_DIR}/soc-access.log combined
</VirtualHost>
EOF

    if [[ "$DISTRO" == "debian" ]]; then a2ensite soc-dash >/dev/null; fi
    apachectl configtest 2>/dev/null || true
    systemctl enable --now apache2 2>/dev/null || systemctl enable --now httpd
    systemctl reload apache2 2>/dev/null || systemctl reload httpd
    ok "Apache vhost live"
fi

# ================================================================
# STEP 9 — Cron (only if the repo ships one)
# ================================================================
step "Cron"
if [[ "$NEEDS_CRON" == "yes" || ( "$NEEDS_CRON" == "auto" && -f "$APP_DIR/cron.php" ) ]]; then
    CRON_FILE="/etc/cron.d/soc-dash"
    cat > "$CRON_FILE" <<EOF
# SOC-Dash scheduled jobs
${CRON_SCHEDULE} ${APP_USER} /usr/bin/php ${APP_DIR}/cron.php >/dev/null 2>&1
EOF
    chmod 644 "$CRON_FILE"
    ok "Cron installed at $CRON_FILE"
else
    ok "No cron needed"
fi

# ================================================================
# STEP 10 — Firewall (best-effort)
# ================================================================
step "Firewall (best-effort)"
if command -v ufw >/dev/null; then
    for cidr in "${ALLOWED_CIDRS[@]}"; do
        ufw allow from "$cidr" to any port 80 proto tcp >/dev/null 2>&1 || true
    done
    ok "ufw rules added"
elif command -v firewall-cmd >/dev/null; then
    for cidr in "${ALLOWED_CIDRS[@]}"; do
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${cidr} port port=80 protocol=tcp accept" >/dev/null 2>&1 || true
    done
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld rules added"
else
    warn "No ufw/firewalld detected — secure manually"
fi

# ================================================================
# STEP 11 — Smoke test
# ================================================================
step "Smoke test"
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1/${ENTRY_PRIMARY}" || echo 000)"
if [[ "$HTTP_CODE" =~ ^(200|301|302|401|403)$ ]]; then
    ok "Local request returned HTTP $HTTP_CODE — server is responding"
else
    warn "Local request returned HTTP $HTTP_CODE — check logs"
fi

# ================================================================
# SUMMARY
# ================================================================
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

${GRN}============================================================
 SOC-Dash deployment complete
============================================================${RST}
  Repo:          ${REPO_URL}
  Directory:     ${APP_DIR}
  Entry points:  ${ENTRY_PRIMARY}  (fallback: ${ENTRY_FALLBACK})
  Web server:    ${WEB_SERVER}
  Server name:   ${SERVER_NAME}
  PHP-FPM sock:  ${PHP_SOCK}
  Database:      ${NEEDS_DB}${NEEDS_DB:+  db=${DB_NAME}  user=${DB_USER}}
  DB password:   ${DB_PASS:-<none>}
  Allowlist:     ${ALLOWED_CIDRS[*]}

  URL:           http://${HOST_IP}/${ENTRY_PRIMARY}

${YLW}Post-deploy checks:${RST}
  1. Open http://${HOST_IP}/ from an allowed IP and verify metrics render.
  2. Save the DB password shown above into your password manager.
  3. (Recommended) Put the site behind HTTPS — add a cert with certbot:
       apt install certbot python3-certbot-nginx && certbot --nginx -d ${SERVER_NAME}
  4. (Recommended) If the app supports a token, set APP_TOKEN and re-run
     to inject it into the config.
  5. Review ${APP_DIR} for anything the README says needs manual editing.
EOF
