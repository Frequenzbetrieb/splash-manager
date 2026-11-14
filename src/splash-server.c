/*
 * splash-server.c — EngineX Splash Manager HTTP server
 * Listens on port 8081, serves a drag-and-drop UI to replace
 * the Engine QML startup splash images.
 *
 * Build (static, musl):
 *   arm-linux-musleabihf-gcc  -O2 -static -o splash-server-armhf   splash-server.c
 *   aarch64-linux-musl-gcc    -O2 -static -o splash-server-aarch64 splash-server.c
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define PORT 8081
#define MAX_BODY (4 * 1024 * 1024)  /* 4 MiB max upload */
#define HDR_BUF 4096
#define RECV_TIMEOUT_SEC 30

/* PNG paths — 3 language packs × 2 aspect ratios = 6 files */
static const char *splash_paths[] = {
    "/data/enginex/ui/packs/en/Skins/Embedded/img/SplashScreen.png",
    "/data/enginex/ui/packs/en/Skins/Embedded/img/SplashScreen_16x9.png",
    "/data/enginex/ui/packs/zh-Hant/Skins/Embedded/img/SplashScreen.png",
    "/data/enginex/ui/packs/zh-Hant/Skins/Embedded/img/SplashScreen_16x9.png",
    "/data/enginex/ui/packs/zh-Hans/Skins/Embedded/img/SplashScreen.png",
    "/data/enginex/ui/packs/zh-Hans/Skins/Embedded/img/SplashScreen_16x9.png",
};
#define N_PATHS (sizeof(splash_paths) / sizeof(splash_paths[0]))

/* Backup directory inside mod state */
static char backup_dir[512];
static char state_dir[512];

/* ── PNG validation ────────────────────────────────────────── */

static const unsigned char png_sig[8] = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A};

static int validate_png(const unsigned char *data, size_t len) {
    if (len < 24) return 0;
    if (memcmp(data, png_sig, 8) != 0) return 0;
    /* check IHDR chunk */
    if (data[12]!='I' || data[13]!='H' || data[14]!='D' || data[15]!='R') return 0;
    unsigned int w = (data[16]<<24)|(data[17]<<16)|(data[18]<<8)|data[19];
    unsigned int h = (data[20]<<24)|(data[21]<<16)|(data[22]<<8)|data[23];
    if (w == 0 || h == 0 || w > 4096 || h > 4096) return 0;
    return 1;
}

/* ── Backup / Restore ──────────────────────────────────────── */

static void make_backup_path(const char *orig, char *out, size_t sz) {
    const char *base = strrchr(orig, '/');
    if (!base) base = orig; else base++;
    /* encode language pack into filename: en__SplashScreen.png */
    const char *packs = strstr(orig, "/packs/");
    if (packs) {
        packs += 7; /* skip "/packs/" */
        const char *end = strchr(packs, '/');
        int plen = end ? (int)(end - packs) : (int)strlen(packs);
        snprintf(out, sz, "%s/%.*s__%s", backup_dir, plen, packs, base);
    } else {
        snprintf(out, sz, "%s/%s", backup_dir, base);
    }
}

static void backup_originals(void) {
    mkdir(backup_dir, 0755);
    char bpath[768];
    char marker[768];
    snprintf(marker, sizeof(marker), "%s/.done", backup_dir);
    if (access(marker, F_OK) == 0) return; /* already backed up */

    for (int i = 0; i < (int)N_PATHS; i++) {
        struct stat st;
        if (stat(splash_paths[i], &st) != 0) continue;
        make_backup_path(splash_paths[i], bpath, sizeof(bpath));

        FILE *src = fopen(splash_paths[i], "rb");
        if (!src) continue;
        FILE *dst = fopen(bpath, "wb");
        if (!dst) { fclose(src); continue; }
        char buf[8192];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            fwrite(buf, 1, n, dst);
        fclose(src);
        fclose(dst);
    }
    /* mark backup complete */
    FILE *m = fopen(marker, "w");
    if (m) { fprintf(m, "backup complete\n"); fclose(m); }
}

static int restore_originals(void) {
    char bpath[768];
    int count = 0;
    for (int i = 0; i < (int)N_PATHS; i++) {
        make_backup_path(splash_paths[i], bpath, sizeof(bpath));
        struct stat st;
        if (stat(bpath, &st) != 0) continue;

        FILE *src = fopen(bpath, "rb");
        if (!src) continue;

        /* write to temp then rename */
        char tmp[512];
        snprintf(tmp, sizeof(tmp), "%s.tmp", splash_paths[i]);
        FILE *dst = fopen(tmp, "wb");
        if (!dst) { fclose(src); continue; }
        char buf[8192];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            fwrite(buf, 1, n, dst);
        fclose(src);
        fflush(dst);
        fsync(fileno(dst));
        fclose(dst);
        rename(tmp, splash_paths[i]);
        count++;
    }
    return count;
}

/* ── Security helpers ──────────────────────────────────────── */

/* Check that Host header is an IP literal or *.local (block DNS rebinding) */
static int valid_host(const char *host) {
    if (!host || !*host) return 0;
    /* strip port */
    char buf[256];
    strncpy(buf, host, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;
    char *colon = strrchr(buf, ':');
    if (colon) *colon = 0;
    /* trim whitespace */
    char *p = buf; while (*p == ' ') p++;
    char *e = p + strlen(p) - 1; while (e > p && *e == ' ') *e-- = 0;

    /* allow [::1] and IPv6 brackets */
    if (p[0] == '[') return 1;
    /* allow IP literals: starts with digit */
    if (p[0] >= '0' && p[0] <= '9') return 1;
    /* allow *.local */
    size_t len = strlen(p);
    if (len >= 6 && strcmp(p + len - 6, ".local") == 0) return 1;
    /* allow localhost */
    if (strcmp(p, "localhost") == 0) return 1;
    return 0;
}

/* Check Origin matches Host (same-origin) */
static int valid_origin(const char *origin, const char *host) {
    if (!origin) return 1; /* no Origin header = not a browser cross-origin request */
    /* extract host part from origin: skip http:// or https:// */
    const char *oh = origin;
    if (strncmp(oh, "http://", 7) == 0) oh += 7;
    else if (strncmp(oh, "https://", 8) == 0) oh += 8;
    /* compare with Host */
    if (!host) return 0;
    /* strip port from both for comparison */
    char obuf[256], hbuf[256];
    strncpy(obuf, oh, sizeof(obuf)-1); obuf[sizeof(obuf)-1] = 0;
    strncpy(hbuf, host, sizeof(hbuf)-1); hbuf[sizeof(hbuf)-1] = 0;
    /* remove trailing slash from origin */
    size_t olen = strlen(obuf);
    if (olen > 0 && obuf[olen-1] == '/') obuf[olen-1] = 0;
    return strcmp(obuf, hbuf) == 0;
}

/* ── HTTP helpers ──────────────────────────────────────────── */

static void send_str(int fd, const char *s) {
    size_t len = strlen(s);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, s + sent, len - sent);
        if (n <= 0) break;
        sent += n;
    }
}

static void send_response(int fd, int code, const char *ct, const char *body, size_t blen) {
    char hdr[512];
    const char *reason = code == 200 ? "OK" : code == 400 ? "Bad Request" :
                         code == 403 ? "Forbidden" : code == 404 ? "Not Found" :
                         code == 405 ? "Method Not Allowed" : "Error";
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "\r\n", code, reason, ct, blen);
    send_str(fd, hdr);
    if (blen > 0) {
        size_t sent = 0;
        while (sent < blen) {
            ssize_t n = write(fd, body + sent, blen - sent);
            if (n <= 0) break;
            sent += n;
        }
    }
}

static void send_text(int fd, int code, const char *msg) {
    send_response(fd, code, "text/plain", msg, strlen(msg));
}

/* ── Embedded HTML ─────────────────────────────────────────── */

static const char html_page[] =
"<!DOCTYPE html><html><head><meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>EngineX Splash Manager</title>"
"<style>"
"*{margin:0;padding:0;box-sizing:border-box}"
"body{background:#1a1a2e;color:#e0e0e0;font-family:-apple-system,sans-serif;"
"min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}"
".container{max-width:700px;width:90%;text-align:center}"
"h1{font-size:1.8em;margin-bottom:.3em;color:#fff}"
"h2{font-size:1em;color:#888;margin-bottom:2em;font-weight:normal}"
".drop{border:3px dashed #444;border-radius:16px;padding:60px 20px;cursor:pointer;transition:all .3s}"
".drop:hover,.drop.over{border-color:#00d4ff;background:rgba(0,212,255,.05)}"
".drop p{font-size:1.2em;color:#aaa;pointer-events:none}"
".drop .icon{font-size:3em;margin-bottom:.5em;display:block}"
".preview{margin-top:2em}.preview img{max-width:100%;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,.5)}"
".current{margin-top:2em;opacity:.7}.current img{max-width:100%;border-radius:8px}"
".status{margin-top:1.5em;padding:12px 20px;border-radius:8px;display:none}"
".status.ok{display:block;background:#0a3d0a;color:#4caf50}"
".status.err{display:block;background:#3d0a0a;color:#f44}"
".status.uploading{display:block;background:#1a1a3d;color:#00d4ff}"
".hint{margin-top:.5em;font-size:.85em;color:#666}"
"button{background:#00d4ff;color:#000;border:none;padding:12px 32px;border-radius:8px;"
"font-size:1em;cursor:pointer;margin-top:1em;font-weight:bold}"
"button:hover{background:#00b8d4}button:disabled{opacity:.5;cursor:not-allowed}"
".restore-btn{background:#555;color:#fff;margin-left:1em}"
".restore-btn:hover{background:#777}"
"</style></head><body><div class='container'>"
"<h1>EngineX Splash Manager</h1>"
"<h2>Custom Engine QML Startup Splash</h2>"
"<div class='drop' id='drop'>"
"<span class='icon'>&#x1F3A8;</span>"
"<p>Drop a PNG image here<br>"
"<small>1280&#xd7;800 (16:10) or 1366&#xd7;768 (16:9) recommended</small></p>"
"<input type='file' id='file' accept='image/png' style='display:none'>"
"</div>"
"<div class='hint'>The image will be applied to both 16:10 and 16:9 screen variants.</div>"
"<div class='preview' id='preview' style='display:none'>"
"<h3 style='margin-bottom:.5em'>New splash:</h3>"
"<img id='previewImg'><br>"
"<button id='uploadBtn' onclick='doUpload()'>Apply as Splash</button>"
"<button class='restore-btn' onclick='doRestore()'>Restore Default</button>"
"</div>"
"<div class='status' id='status'></div>"
"<div class='current'>"
"<h3 style='margin-bottom:.5em'>Current splash:</h3>"
"<img src='/current.png' onerror='this.parentElement.style.display=\"none\"'>"
"</div>"
"<div style='margin-top:2em'>"
"<button class='restore-btn' onclick='doRestore()'>Restore Default Splash</button>"
"</div>"
"</div><script>"
"var fileData=null,drop=document.getElementById('drop'),"
"fi=document.getElementById('file');"
"drop.onclick=function(){fi.click()};"
"drop.ondragover=function(e){e.preventDefault();drop.classList.add('over')};"
"drop.ondragleave=function(){drop.classList.remove('over')};"
"drop.ondrop=function(e){e.preventDefault();drop.classList.remove('over');handleFile(e.dataTransfer.files[0])};"
"fi.onchange=function(){handleFile(fi.files[0])};"
"function handleFile(f){"
"if(!f||!f.name.match(/\\.png$/i)){showStatus('err','Please select a PNG file');return}"
"var r=new FileReader();r.onload=function(e){"
"fileData=new Uint8Array(e.target.result);"
"document.getElementById('previewImg').src=URL.createObjectURL(f);"
"document.getElementById('preview').style.display='block';"
"showStatus('','')};r.readAsArrayBuffer(f)}"
"function doUpload(){"
"if(!fileData)return;"
"var btn=document.getElementById('uploadBtn');btn.disabled=true;"
"showStatus('uploading','Uploading...');"
"var x=new XMLHttpRequest();x.open('POST','/upload');"
"x.setRequestHeader('Content-Type','image/png');"
"x.onload=function(){"
"if(x.status==200){showStatus('ok','Splash updated! Reboot to see it.');btn.disabled=false;"
"document.querySelector('.current img').src='/current.png?t='+Date.now()}"
"else{showStatus('err','Upload failed: '+x.responseText);btn.disabled=false}};"
"x.onerror=function(){showStatus('err','Connection error');btn.disabled=false};"
"x.send(fileData)}"
"function doRestore(){"
"if(!confirm('Restore the original default splash screen?'))return;"
"showStatus('uploading','Restoring...');"
"var x=new XMLHttpRequest();x.open('POST','/restore');"
"x.setRequestHeader('Content-Type','application/x-restore');"
"x.onload=function(){"
"if(x.status==200){showStatus('ok','Default splash restored! Reboot to see it.');"
"document.querySelector('.current img').src='/current.png?t='+Date.now()}"
"else{showStatus('err','Restore failed: '+x.responseText)}};"
"x.onerror=function(){showStatus('err','Connection error')};"
"x.send('')}"
"function showStatus(cls,msg){"
"var s=document.getElementById('status');s.className='status';"
"if(cls){s.classList.add(cls);s.textContent=msg}}"
"</script></body></html>";

/* ── Request handling ──────────────────────────────────────── */

static char *find_header(char *headers, const char *name) {
    size_t nlen = strlen(name);
    char *p = headers;
    while (*p) {
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            p += nlen + 1;
            while (*p == ' ') p++;
            char *end = strstr(p, "\r\n");
            if (end) *end = 0;
            return p;
        }
        char *next = strstr(p, "\r\n");
        if (!next) break;
        p = next + 2;
    }
    return NULL;
}

static int write_splash(const unsigned char *data, size_t len) {
    int ok = 0;
    for (int i = 0; i < (int)N_PATHS; i++) {
        /* ensure parent directory exists */
        char dir[512];
        strncpy(dir, splash_paths[i], sizeof(dir)-1);
        dir[sizeof(dir)-1] = 0;
        char *slash = strrchr(dir, '/');
        if (slash) { *slash = 0; /* mkdir -p not needed, dirs should exist */ }

        char tmp[512];
        snprintf(tmp, sizeof(tmp), "%s.tmp", splash_paths[i]);
        int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) continue;
        size_t written = 0;
        while (written < len) {
            ssize_t n = write(fd, data + written, len - written);
            if (n <= 0) break;
            written += n;
        }
        fsync(fd);
        close(fd);
        if (written == len && rename(tmp, splash_paths[i]) == 0)
            ok++;
        else
            unlink(tmp);
    }
    return ok;
}

static void handle_client(int cfd) {
    /* set receive timeout */
    struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char hdr[HDR_BUF];
    size_t hdr_len = 0;
    int hdr_done = 0;

    /* read headers */
    while (hdr_len < HDR_BUF - 1) {
        ssize_t n = read(cfd, hdr + hdr_len, 1);
        if (n <= 0) { close(cfd); return; }
        hdr_len++;
        if (hdr_len >= 4 &&
            hdr[hdr_len-4]=='\r' && hdr[hdr_len-3]=='\n' &&
            hdr[hdr_len-2]=='\r' && hdr[hdr_len-1]=='\n') {
            hdr_done = 1;
            break;
        }
    }
    if (!hdr_done) { send_text(cfd, 400, "Headers too large"); close(cfd); return; }
    hdr[hdr_len] = 0;

    /* parse request line */
    char method[16] = {0}, path[256] = {0};
    sscanf(hdr, "%15s %255s", method, path);

    /* find headers */
    char *host_val = find_header(hdr, "Host");
    char *origin_val = find_header(hdr, "Origin");
    char *ct_val = find_header(hdr, "Content-Type");
    char *cl_val = find_header(hdr, "Content-Length");

    /* ── Security checks ── */
    /* Host header: must be IP literal, localhost, or *.local */
    if (!valid_host(host_val)) {
        send_text(cfd, 403, "Forbidden: invalid Host header");
        close(cfd);
        return;
    }
    /* Origin check on state-changing requests */
    if (strcmp(method, "POST") == 0) {
        if (!valid_origin(origin_val, host_val)) {
            send_text(cfd, 403, "Forbidden: origin mismatch");
            close(cfd);
            return;
        }
    }

    /* ── Routes ── */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
        send_response(cfd, 200, "text/html", html_page, sizeof(html_page) - 1);
    }
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/current.png") == 0) {
        /* serve current splash from first existing path */
        int served = 0;
        for (int i = 0; i < (int)N_PATHS; i++) {
            FILE *f = fopen(splash_paths[i], "rb");
            if (!f) continue;
            fseek(f, 0, SEEK_END);
            long flen = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (flen > 0 && flen < MAX_BODY) {
                unsigned char *buf = malloc(flen);
                if (buf && fread(buf, 1, flen, f) == (size_t)flen) {
                    send_response(cfd, 200, "image/png", (char*)buf, flen);
                    served = 1;
                }
                free(buf);
            }
            fclose(f);
            if (served) break;
        }
        if (!served) send_text(cfd, 404, "No splash image found");
    }
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/upload") == 0) {
        /* Content-Type must be image/png (CORS simple types don't include this → preflight required) */
        if (!ct_val || strncmp(ct_val, "image/png", 9) != 0) {
            send_text(cfd, 400, "Content-Type must be image/png");
            close(cfd);
            return;
        }
        if (!cl_val) {
            send_text(cfd, 400, "Missing Content-Length");
            close(cfd);
            return;
        }
        size_t body_len = (size_t)atol(cl_val);
        if (body_len == 0 || body_len > MAX_BODY) {
            send_text(cfd, 400, "Invalid body size (max 4 MiB)");
            close(cfd);
            return;
        }
        unsigned char *body = malloc(body_len);
        if (!body) { send_text(cfd, 400, "Out of memory"); close(cfd); return; }
        size_t received = 0;
        while (received < body_len) {
            ssize_t n = read(cfd, body + received, body_len - received);
            if (n <= 0) break;
            received += n;
        }
        if (received != body_len) {
            free(body);
            send_text(cfd, 400, "Incomplete body");
            close(cfd);
            return;
        }
        if (!validate_png(body, body_len)) {
            free(body);
            send_text(cfd, 400, "Not a valid PNG (max 4096x4096)");
            close(cfd);
            return;
        }
        int ok = write_splash(body, body_len);
        free(body);
        if (ok > 0) send_text(cfd, 200, "OK");
        else send_text(cfd, 400, "Could not write splash files");
    }
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/restore") == 0) {
        /* Content-Type must be our custom type (forces preflight) */
        if (!ct_val || strncmp(ct_val, "application/x-restore", 21) != 0) {
            send_text(cfd, 400, "Content-Type must be application/x-restore");
            close(cfd);
            return;
        }
        int count = restore_originals();
        if (count > 0) send_text(cfd, 200, "OK");
        else send_text(cfd, 400, "No backup found or restore failed");
    }
    else {
        send_text(cfd, 404, "Not found");
    }
    close(cfd);
}

/* ── Main ──────────────────────────────────────────────────── */

static volatile int running = 1;
static void sighandler(int sig) { (void)sig; running = 0; }

int main(void) {
    /* determine state directory */
    const char *env_state = getenv("ENGINEX_MOD_STATE");
    if (env_state && *env_state) {
        snprintf(state_dir, sizeof(state_dir), "%s/splash-manager", env_state);
    } else {
        snprintf(state_dir, sizeof(state_dir), "/data/enginex/mods-state/splash-manager");
    }
    snprintf(backup_dir, sizeof(backup_dir), "%s/backup", state_dir);
    mkdir(state_dir, 0755);

    /* backup originals before first use */
    backup_originals();

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sfd);
        return 1;
    }
    if (listen(sfd, 8) < 0) {
        perror("listen");
        close(sfd);
        return 1;
    }

    fprintf(stderr, "Splash server listening on port %d\n", PORT);

    while (running) {
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);
        int cfd = accept(sfd, (struct sockaddr*)&cli, &cli_len);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        handle_client(cfd);
    }

    close(sfd);
    return 0;
}
