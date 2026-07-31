#!/usr/bin/env bash
#
# Drosera smoke test: exercises a running stack end to end.
#
# preflight.sh proves the code parses. This proves it actually works: ports
# answer, the renderer produces a real GIF from a real .cast, Elasticsearch has
# documents in it. Run it after `docker compose up -d` has settled.
#
# It writes one clearly-marked test recording into storage/ and removes it
# afterwards. It never touches captured attacker data.
#
#   ./deploy/smoke-test.sh            # honeypot + camera
#   ./deploy/smoke-test.sh --elastic  # also check the search stack

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR" || exit 1

WITH_ELASTIC=0
[ "${1:-}" = "--elastic" ] && WITH_ELASTIC=1

FAILED=0
pass() { printf '  \033[32mok\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=$((FAILED + 1)); }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$1"; }
head2() { printf '\n\033[1m%s\033[0m\n' "$1"; }

STAMP="19700101T000000"
TEST_STEM="203.0.113.253_${STAMP}_ssh"
TEST_CAST="storage/sessions/${TEST_STEM}.cast"
TEST_META="storage/sessions/${TEST_STEM}.meta.json"
TEST_MARK="storage/sessions/${TEST_STEM}.cam.json"
TEST_GIF="storage/clips/${TEST_STEM}.gif"

cleanup() {
    rm -f "$TEST_CAST" "$TEST_META" "$TEST_MARK" "$TEST_GIF" \
          "storage/clips/${TEST_STEM}.mp4" 2>/dev/null || true
}
trap cleanup EXIT

# ------------------------------------------------------------------- containers

head2 "Containers"

while IFS= read -r name; do
    [ -z "$name" ] && continue
    state=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo unknown)
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
             "$name" 2>/dev/null || echo none)
    if [ "$state" != "running" ]; then
        fail "$name state=$state"
    elif [ "$health" = "unhealthy" ]; then
        fail "$name unhealthy"
    else
        pass "$name ($state${health:+, }${health#none})"
    fi
done < <(docker ps -a --filter 'name=hp-' --format '{{.Names}}' | sort)

# ------------------------------------------------------------------------ ports

head2 "Listening ports"

check_port() {
    local port="$1" label="$2"
    # /dev/tcp avoids depending on nc being installed.
    if timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
        pass "${label} (:${port})"
    else
        fail "${label} (:${port}) not accepting connections"
    fi
}

check_port 22   "ssh honeypot"
check_port 21   "ftp honeypot"
check_port 23   "telnet honeypot"
check_port 25   "smtp honeypot"
check_port 80   "web"
check_port 3306 "mysql honeypot"
check_port 445  "smb honeypot"
check_port 3389 "rdp honeypot"

# Banner check: the SSH honeypot should present an OpenSSH version string.
banner=$(timeout 8 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22; head -c 40 <&3' 2>/dev/null || true)
case "$banner" in
    SSH-2.0-OpenSSH*) pass "ssh banner: ${banner%%$'\r'*}" ;;
    "")               fail "ssh banner empty (tarpit engaged for 127.0.0.1?)" ;;
    *)                warn "unexpected ssh banner: ${banner}" ;;
esac

# ------------------------------------------------------------------- public site

head2 "Public site"

# `/` is rendered by public_site/home.php, which fills the persona into the
# index.html template. Two ways this fails silently: PHP-FPM is down, so the
# front door 502s; or nginx still has the old config and serves the raw
# template, publishing "{{COMPANY_NAME}}" to anyone who looks.
home=$(curl -fsS --max-time 10 http://127.0.0.1/ 2>/dev/null || true)

if [ -z "$home" ]; then
    fail "homepage returned nothing (php-fpm down, or tarpit engaged for 127.0.0.1)"
elif printf '%s' "$home" | grep -q '{{'; then
    fail "homepage served with placeholders unfilled -- nginx is still routing / to index.html"
    printf '%s\n' "        docker compose up -d --force-recreate web"
else
    title=$(printf '%s' "$home" | sed -n 's/.*<title>\(.*\)<\/title>.*/\1/p' | head -1)
    pass "homepage renders${title:+: $title}"
fi

# The template must never be reachable directly, or the placeholders leak.
# No -f here: a 404 is the pass condition, and -f would suppress the code.
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
       http://127.0.0.1/index.html 2>/dev/null || echo 000)
case "$code" in
    404) pass "/index.html goes to the trap (404)" ;;
    200) fail "/index.html serves the raw template -- placeholders are public" ;;
    *)   warn "/index.html returned ${code}" ;;
esac

if [ -f "${REPO_DIR:-.}/persona/persona.json" ]; then
    pass "persona present (this deployment has its own fingerprint)"
else
    warn "no persona: running the defaults published in this repo"
    warn "  ./deploy/generate-persona.sh && docker compose up -d"
fi

# ------------------------------------------------------------------- dashboard

head2 "Operator dashboard"

if code=$(docker exec hp-admin-dashboard python3 -c \
        "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8443/healthz',timeout=5).status)" \
        2>/dev/null); then
    [ "$code" = "200" ] && pass "/healthz returned 200" || fail "/healthz returned ${code}"
else
    fail "dashboard healthz unreachable"
fi

# -------------------------------------------------------------- session camera

head2 "Session camera"

mkdir -p storage/sessions storage/clips 2>/dev/null || true

# A minimal but genuine asciicast v2: header, then output frames including an
# escape sequence, so the renderer's terminal emulation is actually exercised.
cat > "$TEST_CAST" <<'CAST'
{"version":2,"width":80,"height":24,"timestamp":0,"title":"smoke test","env":{"TERM":"xterm-256color"}}
[0.0,"o","root@prod-web-01:~# "]
[0.4,"o","uname -a\r\n"]
[0.5,"o","Linux prod-web-01 5.15.0-86-generic #1 SMP x86_64 GNU/Linux\r\n"]
[1.0,"o","root@prod-web-01:~# "]
[1.4,"o","cat /etc/shadow\r\n"]
[1.5,"o","[31mroot:$6$xyz:19000:0:99999:7:::[0m\r\n"]
[2.0,"o","root@prod-web-01:~# "]
CAST

if [ -f "$TEST_CAST" ]; then
    pass "wrote synthetic recording"
else
    fail "could not write into storage/sessions (ownership?)"
fi

if out=$(docker compose exec -T session-cam python3 cam.py --render \
         "/var/honeypot/storage/sessions/${TEST_STEM}.cast" 2>&1); then
    if [ -f "$TEST_GIF" ]; then
        size=$(wc -c < "$TEST_GIF" | tr -d ' ')
        if [ "$size" -gt 2000 ]; then
            pass "rendered GIF, ${size} bytes"
        else
            fail "GIF is only ${size} bytes -- likely a blank render"
        fi
        # GIF87a/GIF89a magic. A truncated or mis-encoded file fails here.
        if head -c 6 "$TEST_GIF" | grep -q 'GIF8'; then
            pass "GIF header valid"
        else
            fail "output is not a GIF"
        fi
    else
        fail "renderer reported success but produced no file"
        printf '%s\n' "$out" | sed 's/^/        /'
    fi
else
    fail "renderer errored"
    printf '%s\n' "$out" | sed 's/^/        /'
fi

# -------------------------------------------------------------- search stack

if [ "$WITH_ELASTIC" -eq 1 ]; then
    head2 "Elasticsearch"

    if [ -f .env ]; then
        # shellcheck disable=SC1091
        set -a; . ./.env 2>/dev/null || true; set +a
    fi

    if [ "${ELASTIC_PASSWORD:-}" = "" ]; then
        fail "ELASTIC_PASSWORD not set; cannot query"
    else
        if health=$(docker exec hp-elasticsearch curl -fsS \
                    -u "elastic:${ELASTIC_PASSWORD}" \
                    'http://127.0.0.1:9200/_cluster/health' 2>/dev/null); then
            case "$health" in
                *'"status":"green"'*|*'"status":"yellow"'*)
                    pass "cluster health ok (yellow is correct for one node)" ;;
                *)  fail "cluster health: ${health}" ;;
            esac
        else
            fail "elasticsearch not answering"
        fi

        prefix="${ELASTIC_INDEX_PREFIX:-drosera}"
        if count=$(docker exec hp-elasticsearch curl -fsS \
                   -u "elastic:${ELASTIC_PASSWORD}" \
                   "http://127.0.0.1:9200/${prefix}-*/_count" 2>/dev/null); then
            docs=$(printf '%s' "$count" | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
            if [ "${docs:-0}" -gt 0 ]; then
                pass "${docs} events indexed"
            else
                warn "0 events indexed -- expected if nothing has hit the honeypot yet"
            fi
        else
            fail "could not query ${prefix}-* count"
        fi

        # ILM is the thing most likely to be silently broken.
        if ilm=$(docker exec hp-elasticsearch curl -fsS \
                 -u "elastic:${ELASTIC_PASSWORD}" \
                 "http://127.0.0.1:9200/${prefix}-*/_ilm/explain" 2>/dev/null); then
            case "$ilm" in
                *'"step":"ERROR"'*) fail "ILM is in an ERROR step" ;;
                *)                  pass "no ILM errors" ;;
            esac
        fi
    fi

    if docker exec hp-kibana curl -fsS 'http://127.0.0.1:5601/api/status' \
            >/dev/null 2>&1; then
        pass "kibana answering"
    else
        warn "kibana not ready yet (it takes a minute or two after start)"
    fi
fi

# ------------------------------------------------------------------ containment

head2 "Containment"

# The whole security model rests on this: honeypot containers must not reach the
# internet, and session-cam must.
if docker exec hp-ssh-honey timeout 6 python3 -c \
        "import socket;socket.create_connection(('1.1.1.1',53),timeout=4)" \
        >/dev/null 2>&1; then
    fail "ssh-honey REACHED THE INTERNET -- containment is broken"
else
    pass "ssh-honey has no egress"
fi

if docker exec hp-web timeout 6 sh -c \
        'php -r "exit(@fsockopen(\"1.1.1.1\",53,\$e,\$s,4)?0:1);"' >/dev/null 2>&1; then
    fail "web REACHED THE INTERNET -- containment is broken"
else
    pass "web has no egress"
fi

if docker exec hp-session-cam timeout 10 python3 -c \
        "import socket;socket.create_connection(('1.1.1.1',53),timeout=6)" \
        >/dev/null 2>&1; then
    pass "session-cam has egress (required for delivery)"
else
    warn "session-cam has no egress; clip delivery will fail"
fi

# Containment is only half the model. The other half is that the containers
# which are SUPPOSED to talk to each other still can -- and that half had no
# test, which is how a deployment reached production where no honeypot could
# reach Redis at all. It fails silently by design: identities stop being
# tracked, scores stop accumulating, bans stop applying, and the only visible
# symptom is a dashboard that looks like a quiet day.
#
# The usual cause is `icc: false` in /etc/docker/daemon.json becoming the
# inherited default for a user-defined bridge created after it. docker-compose
# sets enable_icc explicitly to prevent that; this asserts it worked.
for container in hp-ssh-honey hp-admin-dashboard; do
    if docker exec "$container" timeout 8 python3 -c \
            "import socket;socket.create_connection(('redis-honeypot',6379),timeout=5)" \
            >/dev/null 2>&1; then
        pass "${container#hp-} reaches redis-honeypot"
    else
        fail "${container#hp-} CANNOT reach redis-honeypot -- no identities, scores or bans"
    fi
done

if docker exec hp-admin-dashboard timeout 8 python3 -c \
        "import socket;socket.create_connection(('redis-admin',6379),timeout=5)" \
        >/dev/null 2>&1; then
    pass "admin-dashboard reaches redis-admin"
else
    fail "admin-dashboard CANNOT reach redis-admin -- sessions and audit will fail"
fi

printf '\n'
if [ "$FAILED" -gt 0 ]; then
    printf '\033[31m%d check(s) failed\033[0m\n' "$FAILED"
    exit 1
fi
printf '\033[32mAll checks passed\033[0m\n'
exit 0
