# RstPrx — Elite Rama Reverse Proxy

A **100% stealth reverse proxy** built in Rust with the [Rama](https://github.com/plabayo/rama) framework. Designed to be undetectable by anti-proxy systems.

## Features

### Stealth
- **JA3/JA4+ TLS fingerprint spoofing** — mimics real browsers
- **Browser profile correlation** — UA, sec-ch-ua, Accept, HTTP/2 settings all match as a unit (Chrome 131, Firefox 133, Safari 18, Edge 120)
- **Header order preservation** — browser-specific header ordering
- **HTTP/2 SETTINGS fingerprint** — Akamai fingerprint mimicry
- **WebSocket fingerprint** — browser-specific handshake headers
- **TLS GREASE temporal jitter** — micro-delays to avoid timing analysis
- **Behavioral mimicry** — human-like request patterns with referer tracking
- **Response sanitization** — strips 21 target-identifying headers, injects `Server: nginx/1.24.0`
- **Fake website** — visitors see a "Coming Soon" page, not a proxy

### Security
- **JWT authentication** with Argon2 password hashing
- **Rate limiting** per IP and per domain
- **Circuit breaker** for upstream failure protection
- **Path traversal protection** on all file operations
- **API/Metrics auth required** — no unauthenticated access

### Infrastructure
- **Pure Rust TLS** via rustls (no OpenSSL dependency)
- **Auto self-signed certificates** with rcgen
- **ACME/Let's Encrypt ready** (DNS-01 + HTTP-01)
- **Prometheus metrics** endpoint
- **Systemd service** with security hardening
- **Docker support**

## Quick Install (VPS)

```bash
# Clone the repository
git clone https://github.com/speedshadow/rstprx.git
cd rstprx

# Run the automated installer (as root)
sudo bash install.sh
```

### Ubuntu/Debian fully automatic install (no prompts)

```bash
sudo bash install.sh --auto --force
```

Optional flags for automation:

```bash
# Set a fixed admin password (min 12 chars)
sudo bash install.sh --auto --force --admin-password 'YourStrongPassword123!'

# Generate cert for a specific domain instead of IP self-signed cert
sudo bash install.sh --auto --force --domain proxy.example.com
```

The installer handles everything:
1. Detects your OS (Ubuntu, Debian, Fedora, CentOS, RHEL, Rocky, AlmaLinux)
2. Installs dependencies + Rust
3. Compiles the project
4. Generates admin password + JWT secret
5. Creates SSL certificates (self-signed or for your domain)
6. Creates systemd service with auto-restart
7. Configures firewall
8. Tests the installation

After install:
- **Admin Panel**: `https://YOUR_IP:8443/admin_elite/login`
- **Fake Website**: `https://YOUR_IP:8443/`
- **Credentials**: saved in `/opt/rama-proxy/CREDENTIALS.txt`

## Manual Build

```bash
# Requirements: Rust 1.91+ (no cmake/openssl needed — pure rustls)
cargo build --release

# Run
./target/release/rama-elite-proxy --config config.yaml

# Run tests
cargo test
```

## Configuration

Edit `config.yaml`:

```yaml
server:
  listen_addr: "0.0.0.0:8443"
  admin_path: "/admin_elite"        # Secret admin URL
  fake_website_enabled: true         # Show fake site to visitors
  tls:
    enabled: true
    mode: "selfsigned"               # or "autocert" for Let's Encrypt

proxy:
  profiles:
    enabled: true
    browsers: ["chrome_131", "firefox_133", "safari_18", "edge_120"]

stealth:
  remove_headers:                    # Headers stripped from requests
    - "X-Forwarded-For"
    - "Via"
    - "CF-Connecting-IP"
  header_order:
    preserve: true                   # Browser-correct header ordering
```

## DNS Setup (for VPS)

The proxy uses the **system DNS resolver** by default (`/etc/resolv.conf`).

### How to point a domain to your proxy:

1. **Buy a domain** (e.g., `example.com`)
2. **Create an A record** pointing to your VPS IP:
   ```
   A    proxy.example.com    →    YOUR_VPS_IP
   ```
3. **Add the domain** in the admin panel (`/admin_elite`) with the target URL
4. **Access via domain**: `https://proxy.example.com:8443/`

### DNS Resolution Flow:
```
User → DNS (proxy.example.com → VPS IP) → VPS:8443 → Proxy → Target Site
```

The proxy resolves target hostnames using the VPS system resolver. A `DnsFingerprinter` module is available for DNS-over-HTTPS (DoH) via Cloudflare/Google/Quad9, emulating browser-specific DNS patterns (Chrome prefers IPv4, Firefox prefers IPv6).

## How It Works

```
Client Request
    │
    ▼
┌─ TLS Handshake (JA3/JA4 spoofing) ─┐
│  Rate Limiter → Circuit Breaker      │
│                                      │
│  Route: /admin → Frontend (fake web) │
│  Route: other  → Proxy Pipeline      │
│                                      │
│  STEALTH PIPELINE:                   │
│  1. Strip proxy headers              │
│  2. Select browser profile           │
│  3. Inject sec-ch-ua hints           │
│  4. Enforce header order             │
│  5. WebSocket fingerprint            │
│  6. Behavioral mimicry               │
│  7. TLS GREASE jitter               │
│                                      │
│  HTTPS → Target Site (pooled)        │
│                                      │
│  Response: sanitize headers          │
│  + Server: nginx/1.24.0             │
└──────────────────────────────────────┘
    │
    ▼
Client receives response
(indistinguishable from direct browser access)
```

## Service Management

```bash
systemctl status rama-proxy     # Check status
systemctl restart rama-proxy    # Restart
journalctl -u rama-proxy -f     # Live logs
```

## Project Structure

```
src/
├── main.rs              # Entry point
├── server.rs            # TCP/TLS listener, request routing
├── config.rs            # YAML configuration parsing
├── proxy/
│   ├── handler.rs       # Core proxy logic + stealth pipeline
│   ├── director.rs      # URL rewriting for target
│   ├── rewriter.rs      # IPTV/M3U content rewriting
│   └── streaming.rs     # Large response streaming
├── stealth/
│   ├── headers.rs       # Header cleaning + sec-ch-ua injection
│   ├── header_order.rs  # Browser-specific header ordering
│   ├── tls_grease.rs    # JA3/JA4 + GREASE + temporal jitter
│   ├── http2_advanced.rs # HTTP/2 SETTINGS fingerprint
│   ├── websocket_fingerprint.rs
│   ├── dns_fingerprint.rs
│   ├── behavioral.rs    # Human-like request patterns
│   ├── user_agent.rs    # UA pool management
│   └── path_sanitizer.rs
├── auth.rs              # JWT + Argon2
├── frontend.rs          # Admin panel + fake website
├── tls.rs               # Certificate generation
├── tls_manager.rs       # Per-domain SNI certificates
├── rate_limit.rs        # Governor-based rate limiting
├── circuit_breaker.rs   # Upstream failure protection
├── metrics.rs           # Prometheus metrics
└── acme/                # Let's Encrypt integration
```

## License

MIT
