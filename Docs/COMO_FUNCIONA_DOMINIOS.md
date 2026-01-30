# 🌐 Como Funciona o Sistema de Domínios

## 📋 Resumo

O proxy possui **3 modos de operação** dependendo do domínio/IP acessado:

---

## 🔐 Modo 1: ADMIN (Secret Path)

**Acesso:** `https://qualquer-dominio.com/admin_elite`

**Comportamento:**
- ✅ Requer autenticação (JWT + Cookie)
- ✅ Se não autenticado → Redirect para `/admin_elite/login`
- ✅ Se autenticado → Dashboard de gestão

**Exemplo:**
```bash
https://45.67.89.123/admin_elite         → Pede login
https://meudominio.com/admin_elite       → Pede login
https://app.cliente1.com/admin_elite     → Pede login (mas escondido!)
```

---

## 🎭 Modo 2: FAKE WEBSITE (Domínio Não Configurado)

**Quando acontece:**
- Domínio/IP NÃO está configurado no painel admin
- Acesso direto ao path raiz `/`

**Comportamento:**
- ✅ Mostra página "Coming Soon" genérica
- ✅ ZERO menções a proxy/nginx/admin
- ✅ Bots/Scanners pensam que é site normal

**Exemplo:**
```bash
# Compraste dominio.com e apontaste DNS A para VPS
# MAS ainda NÃO configuraste no painel

https://dominio.com/              → "Coming Soon" 🎭
https://outro-dominio.com/        → "Coming Soon" 🎭
https://45.67.89.123/             → "Coming Soon" 🎭
```

---

## 🔄 Modo 3: PROXY REVERSO (Domínio Configurado)

**Quando acontece:**
- Domínio está adicionado no painel admin
- Storage tem: `cliente1.com → http://target.com:8080`

**Comportamento:**
- ✅ Faz proxy transparente para o target
- ✅ Headers preservados
- ✅ TLS/SSL automático
- ✅ Rate limiting aplicado

**Exemplo:**
```bash
# No painel admin adicionaste:
# Domínio: app.cliente1.com
# Target: http://192.168.1.100:3000

https://app.cliente1.com/         → Proxy para http://192.168.1.100:3000/
https://app.cliente1.com/api/data → Proxy para http://192.168.1.100:3000/api/data
```

---

## 🏗️ Cenários Práticos

### **Cenário 1: Setup Inicial VPS**

```
1. VPS IP: 45.67.89.123
2. Instalas proxy e deixa rodando
3. Alguém acessa: https://45.67.89.123/

✅ RESULTADO: Mostra "Coming Soon" (fake website)
✅ Ninguém sabe que é um proxy!
```

### **Cenário 2: Adicionar Primeiro Domínio**

```
1. Compras: meudominio.com
2. DNS: meudominio.com A → 45.67.89.123
3. Acessa: https://meudominio.com/

✅ RESULTADO: Ainda mostra "Coming Soon" (não configurado!)

4. Vais no painel: https://meudominio.com/admin_elite
5. Login com admin/senha
6. Adiciona domínio:
   - Domínio: meudominio.com
   - Target: http://servidor-interno.com

✅ AGORA: https://meudominio.com/ → Proxy para servidor-interno.com
```

### **Cenário 3: Múltiplos Clientes com Subdomínios**

```
Setup DNS Wildcard:
*.proxies.com A → 45.67.89.123

No painel admin, adicionas:
1. cliente1.proxies.com → http://app1.interno:8080
2. cliente2.proxies.com → http://app2.interno:9000
3. cliente3.proxies.com → http://app3.interno:3000

Resultados:
https://cliente1.proxies.com/  → Proxy para app1 ✅
https://cliente2.proxies.com/  → Proxy para app2 ✅
https://cliente3.proxies.com/  → Proxy para app3 ✅
https://outro.proxies.com/     → "Coming Soon" 🎭 (não configurado)
https://proxies.com/           → "Coming Soon" 🎭 (domínio raiz não configurado)
```

### **Cenário 4: Stealth Máximo**

```
Tens VPS com 10 domínios diferentes apontados
Só 3 estão configurados como proxy

Resultado:
- 3 domínios → Funcionam como proxy
- 7 domínios → Mostram "Coming Soon"
- IP direto → Mostra "Coming Soon"
- Path /admin_elite → Sempre funciona (mas secreto!)

✅ Scanners não descobrem que é proxy
✅ Admin sempre acessível (mas oculto)
✅ Cada cliente tem seu domínio isolado
```

---

## 🔒 Segurança

### **Acesso Admin é SEMPRE Possível**

```bash
# Mesmo que domínio não esteja configurado:
https://qualquer-dominio.com/admin_elite  → Admin ✅
https://45.67.89.123/admin_elite         → Admin ✅

# MAS requer autenticação!
```

### **Proteções Ativas**

1. ✅ Rate limiting por IP
2. ✅ Rate limiting por domínio
3. ✅ JWT com cookies HttpOnly
4. ✅ Argon2 password hashing
5. ✅ Audit logging de tentativas
6. ✅ Fake website para confundir bots

---

## 📊 Fluxo de Decisão

```
Request chega → Extrai Host header e Path

IF path == "/admin_elite/*":
    → Verificar autenticação
    → Se não autenticado: redirect login
    → Se autenticado: dashboard

ELSE IF path == "/" AND Host não configurado:
    → Fake website "Coming Soon"

ELSE IF path == "/" AND Host configurado no storage:
    → Proxy para target configurado

ELSE IF path != "/" AND Host configurado:
    → Proxy para target + path

ELSE:
    → Not Found genérico
```

---

## ✅ Checklist de Setup Produção

### **1. Configuração Inicial VPS**
- [ ] Instalar proxy na VPS
- [ ] Gerar certificados (ou usar ACME)
- [ ] Mudar JWT secret no config.yaml
- [ ] Gerar novo password hash: `cargo run --example hash_password "SuaSenhaSegura"`
- [ ] Iniciar servidor: `./target/release/rama-elite-proxy`

### **2. Configuração DNS**
- [ ] Domínio principal: `A` → IP VPS
- [ ] Wildcard (opcional): `*.dominio.com A` → IP VPS

### **3. Primeiro Acesso**
```bash
# Testa fake website
curl -k https://SEU-IP-VPS/
# Deve mostrar: "Coming Soon"

# Acessa admin
https://SEU-IP-VPS/admin_elite/login
# Login: admin
# Pass: (a que definiste)
```

### **4. Adicionar Domínios Proxy**
No dashboard admin (`/admin_elite`):
1. Clica "Add Domain"
2. Domínio: `cliente1.com`
3. Target: `http://192.168.1.100:8080`
4. Save

### **5. Verificação**
```bash
# Domínio configurado deve fazer proxy
curl -I https://cliente1.com/
# Deve retornar: HTTP 200 (do target)

# Domínio não configurado mostra fake
curl https://outro-dominio.com/
# Deve retornar: "Coming Soon"
```

---

## 🎯 Resposta à Tua Pergunta

> "Se eu comprar domínio e apontar A para o IP da VPS, vai abrir o fake site?"

**SIM!** ✅

**Funcionamento:**
1. Compras `meudominio.com`
2. DNS: `meudominio.com A → 45.67.89.123`
3. Alguém acessa: `https://meudominio.com/`

**Resultado:** Mostra **"Coming Soon"** (fake website)

**Porquê?** O domínio ainda não está no **storage** (não foi adicionado no painel)

**Para fazer proxy:**
1. Acessa: `https://meudominio.com/admin_elite`
2. Login no dashboard
3. Adiciona domínio no painel:
   - Domain: `meudominio.com`
   - Target: `http://servidor-real.com:8080`

**Agora:** `https://meudominio.com/` faz **proxy** para o target! 🎉

---

## 💡 Dica Pro

Para máxima eficiência:

```yaml
# Setup DNS
proxies.meudominio.com A → VPS-IP
*.proxies.meudominio.com A → VPS-IP

# No painel, adiciona só os que queres:
cliente1.proxies.meudominio.com → target1
cliente2.proxies.meudominio.com → target2
cliente3.proxies.meudominio.com → target3

# Resultado:
# - Clientes configurados: funcionam ✅
# - Outros subdomínios: "Coming Soon" 🎭
# - Domínio raiz: "Coming Soon" 🎭
# - Admin sempre em: /admin_elite 🔐
```

---

**Autor:** Elite Rama Proxy Security Team  
**Versão:** 1.0.0 - Production Ready 2026  
**Última atualização:** 30 Janeiro 2026
