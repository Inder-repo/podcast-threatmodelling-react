// ╔══════════════════════════════════════════════════════════════════════╗
// ║  THREAT MODELING MASTERY LAB v4                                      ║
// ║  Interactive DFDs · Architecture origin · Threat↔Mitigation maps    ║
// ║  Animated Attack Tree simulator · STRIDE overlay · No vendor refs    ║
// ╚══════════════════════════════════════════════════════════════════════╝
import { useState, useEffect, useRef, useCallback } from "react";

const _fl = document.createElement("link");
_fl.rel = "stylesheet";
_fl.href = "https://fonts.googleapis.com/css2?family=Bebas+Neue&family=JetBrains+Mono:wght@300;400;600;700&family=Manrope:wght@300;400;500;600;700;800&display=swap";
document.head.appendChild(_fl);

const C = {
  bg:"#06090f", panel:"#0b1018", card:"#0f1621", raised:"#141e2d",
  border:"#1c2d42", borderHi:"#2a4060",
  text:"#d4e4f4", sub:"#6e8aaa", muted:"#3a5270",
  accent:"#2dd4bf", accentD:"#0f4f48",
  blue:"#60a5fa", blueD:"#1e3a5f",
  amber:"#fbbf24", amberD:"#4a3000",
  red:"#f87171", redD:"#3f1010",
  green:"#4ade80", greenD:"#0f3020",
  purple:"#c084fc", purpleD:"#2d1050",
  S:"#f87171", T:"#fb923c", R:"#fbbf24", I:"#60a5fa", D:"#c084fc", E:"#4ade80",
  zones:{
    "Not in Control":{ c:"#6e8aaa", bg:"#0b1018", badge:"Z0" },
    "Minimal Trust": { c:"#4ade80", bg:"#0b1a12", badge:"Z1" },
    "Standard":      { c:"#2dd4bf", bg:"#0b1a18", badge:"Z3" },
    "Elevated":      { c:"#fbbf24", bg:"#1a1200", badge:"Z5" },
    "Critical":      { c:"#f87171", bg:"#1a0b0b", badge:"Z7" },
    "Max Security":  { c:"#c084fc", bg:"#140b1a", badge:"Z9" },
  },
  display:"'Bebas Neue', monospace",
  mono:"'JetBrains Mono', monospace",
  body:"'Manrope', sans-serif",
};

const GCSS = `
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{background:${C.bg};color:${C.text};font-family:${C.body};font-size:14px;line-height:1.6}
  ::-webkit-scrollbar{width:5px;height:5px}
  ::-webkit-scrollbar-track{background:${C.panel}}
  ::-webkit-scrollbar-thumb{background:${C.border};border-radius:3px}
  select,input{appearance:none;-webkit-appearance:none}
  button{font-family:inherit;cursor:pointer}
  @keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  @keyframes flow{0%{stroke-dashoffset:24}100%{stroke-dashoffset:0}}
  @keyframes glow{0%,100%{filter:brightness(1)}50%{filter:brightness(1.6)}}
  .fu{animation:fadeUp .25s ease both}
  .gbg{
    background-image:linear-gradient(${C.border}20 1px,transparent 1px),linear-gradient(90deg,${C.border}20 1px,transparent 1px);
    background-size:44px 44px;
  }
`;

// ── STRIDE encyclopedia ────────────────────────────────────────────────
const STRIDE_GUIDE = [
  { letter:"S", name:"Spoofing",    color:C.S,
    oneLiner:"Pretending to be someone or something you're not.",
    technical:"An attacker presents a false identity — forged token, spoofed IP, fake service — to gain access they aren't authorised for. The system believes the attacker IS who they claim.",
    realExample:"Attacker replays a stolen JWT to access another user's account. The API accepts the token and believes it's communicating with the legitimate user.",
    dfdRule:"Applies to any node reachable from an untrusted (Zone 0) source. The node accepts identity claims it cannot independently verify.",
    defence:"Authentication: require cryptographic proof of identity. Verify token signatures — not structure. Short expiry. Refresh token rotation.",
    question:"Who can claim to be who they're not?",
    quiz:{ q:"User A changes the user_id in a request URL from their own ID to User B's. The API returns User B's orders with no authorisation check. Which STRIDE?",
      opts:["Spoofing","Tampering","Elevation of Privilege","Information Disclosure"], correct:2,
      why:"Elevation of Privilege — User A gained capabilities beyond their authorised role. They didn't claim to BE User B (Spoofing) — they bypassed the authorisation check entirely. OWASP calls this BOLA." }},
  { letter:"T", name:"Tampering",   color:C.T,
    oneLiner:"Maliciously modifying data or code.",
    technical:"An attacker alters data in transit or at rest — modifying a price, injecting SQL, editing a config file — in ways the receiving system cannot detect.",
    realExample:"Attacker modifies a checkout request, changing the item price from £100 to £0.01. The API processes the modified value as legitimate.",
    dfdRule:"Applies to data flows crossing UPWARD (lower trust zone → higher trust zone). The higher-trust component accepts data without independent integrity verification.",
    defence:"Integrity: sign data with HMAC or digital signatures. Use parameterised queries. Validate all inputs server-side, independently of client.",
    question:"Who can modify data or code they shouldn't?",
    quiz:{ q:"An attacker modifies the amount field from $100 to $100,000 after the JWT is validated. The Payment Service processes it because it trusts the upstream gateway's validation. Which STRIDE?",
      opts:["Spoofing","Tampering","Information Disclosure","Denial of Service"], correct:1,
      why:"Tampering: the attacker modified data that the receiving system accepted. JWT validates identity — not data integrity. Fix: re-validate in the Payment Service, not just at the gateway." }},
  { letter:"R", name:"Repudiation", color:C.R,
    oneLiner:"Claiming you didn't do something you actually did.",
    technical:"An action is performed but cannot be attributed to a specific actor — because logging is absent, logs are mutable, or identity verification was weak enough to deny.",
    realExample:"A bank employee deletes a transaction record. No audit log exists. The customer disputes the transfer. The bank cannot prove the transaction happened.",
    dfdRule:"Applies to any node where BOTH Spoofing AND Tampering apply. If identity can be forged AND data altered, no action can be reliably attributed.",
    defence:"Non-repudiation: immutable append-only audit logs. Strong authentication before auditable actions. Distributed tracing with tamper-evident IDs.",
    question:"Who can deny doing something they actually did?",
    quiz:{ q:"A payment processor stores logs in the same database as transactions. An insider deletes both the transaction and the log entry. Which STRIDE best describes the log deletion?",
      opts:["Tampering","Repudiation","Information Disclosure","Elevation of Privilege"], correct:1,
      why:"Repudiation: log deletion removes the ability to prove the action occurred. The original deletion was Tampering — multiple categories can apply to one action." }},
  { letter:"I", name:"Info Disclosure", color:C.I,
    oneLiner:"Exposing data to people who shouldn't see it.",
    technical:"Sensitive data leaks to unauthorised parties — via verbose error messages, insecure transmission, over-permissive APIs, or data cached at the wrong trust level.",
    realExample:"An API returns a 500 error containing the full PostgreSQL stack trace with table names. An attacker uses the schema to craft targeted SQL injection.",
    dfdRule:"Applies to data flows crossing DOWNWARD (higher trust zone → lower trust zone). Sensitive data flowing 'down' may reach unauthorised consumers.",
    defence:"Confidentiality: encrypt in transit and at rest. Least-privilege API responses. Strip internal details from error messages. Cache-Control headers.",
    question:"Who can see data they shouldn't?",
    quiz:{ q:"A multi-tenant SaaS caches query results keyed only by query hash. Two tenants run similar queries — same cache key — and Tenant A receives Tenant B's data. Which STRIDE?",
      opts:["Spoofing","Tampering","Information Disclosure","Elevation of Privilege"], correct:2,
      why:"Information Disclosure: Tenant B's data was exposed to an unauthorised party. Fix: include tenant_id in the cache key." }},
  { letter:"D", name:"Denial of Service", color:C.D,
    oneLiner:"Making a system unavailable to legitimate users.",
    technical:"An attacker exhausts shared resources — CPU, memory, DB connections, API rate limits — so legitimate requests cannot be processed.",
    realExample:"A botnet sends 500,000 requests/second to a checkout endpoint. The DB connection pool (size: 20) exhausts in under 1 second. All genuine checkouts fail.",
    dfdRule:"Applies to any node reachable from Zone 0. Untrusted actors have no resource constraints your system can enforce — they can always send more requests.",
    defence:"Availability: rate limiting at the edge, circuit breakers, auto-scaling, connection pooling, CDN offloading, graceful degradation.",
    question:"Who can make the system unavailable to legitimate users?",
    quiz:{ q:"One tenant's bulk upload script consumes all shared API Gateway connections for 5 minutes. All 499 other tenants receive 503 errors. Which STRIDE?",
      opts:["Spoofing","Tampering","Denial of Service","Elevation of Privilege"], correct:2,
      why:"Denial of Service: shared resources exhausted by one actor, making the service unavailable to others. Fix: per-tenant rate limiting." }},
  { letter:"E", name:"Elevation of Privilege", color:C.E,
    oneLiner:"Gaining more access than you're authorised to have.",
    technical:"An attacker exploits a flaw to gain permissions beyond their role — customer becomes admin, service account gains root, or a tenant accesses another tenant's data.",
    realExample:"Attacker strips the JWT signature and sets role:admin in the payload. Server validates structure but not the algorithm. Admin access granted to a regular customer.",
    dfdRule:"Applies to any node adjacent (connected via a data flow) to a lower-trust zone. That connection is a potential privilege escalation path.",
    defence:"Authorisation: server-side role check on EVERY request. Never trust client-supplied claims. Principle of least privilege. Deny-by-default. Separate admin infrastructure.",
    question:"Who can gain capabilities beyond what they're authorised to have?",
    quiz:{ q:"An employee with read-only DB access discovers ORM debug mode is on in production, allowing arbitrary SQL via a URL parameter. They run DROP TABLE customers. Which STRIDE?",
      opts:["Spoofing","Tampering","Repudiation","Elevation of Privilege"], correct:3,
      why:"Elevation of Privilege: read-only access escalated to arbitrary SQL execution. The debug mode misconfiguration was the EoP vector. (The DROP TABLE is also Tampering — multiple categories can apply.)" }},
];

// ── Workshop data ──────────────────────────────────────────────────────
const WS = {
"1":{
  id:"1", name:"TechMart E-Commerce", subtitle:"2-Tier Web Application",
  level:"FOUNDATION", levelColor:C.green, duration:"90 min",
  access:"FREE", unlockCode:null,
  compliance:["PCI-DSS L4","GDPR","CCPA"],
  businessContext:"Series A · 50K MAU · $2M ARR · EU + US",
  description:"A React SPA sells products and processes payments via Stripe. Orders stored in PostgreSQL. SendGrid sends transactional emails. 5-engineer team, no dedicated security role.",
  archRationale:{
    summary:"TechMart's architecture was not designed — it evolved. Each component was chosen to solve an immediate problem by a small team under time pressure. Understanding those decisions reveals exactly where the security gaps came from.",
    decisions:[
      { title:"Why React SPA?", icon:"⚛",
        reason:"The CTO had React experience and needed to ship fast. The SPA pattern was chosen for developer velocity — not security. Side-effect: all application state, including tokens, lives in the browser where the team has zero control.",
        consequence:"JWT stored in localStorage. No server-side session. Any XSS on any page compromises the entire session. This single decision is the root cause of T-101.",
        alternative:"Server-side sessions with HttpOnly cookies would have moved token storage out of the browser entirely — eliminating the XSS attack surface for credential theft." },
      { title:"Why Node.js API?", icon:"🟩",
        reason:"Same team, same language as the frontend (JavaScript). One codebase to hire for. Express was chosen for its minimal boilerplate. No framework opinions on input validation or query construction.",
        consequence:"Developers write raw SQL template literals by habit — `SELECT * FROM orders WHERE id=${req.query.id}`. Express has no built-in protection. This is the root cause of T-102 and T-103.",
        alternative:"A framework with ORM defaults (e.g. Prisma, TypeORM with parameterised queries enforced) would have made the safe path the easy path — removing SQL injection as a class of vulnerability." },
      { title:"Why PostgreSQL?", icon:"🐘",
        reason:"Relational data model fit the order/product/customer schema. PostgreSQL was the most capable open-source option. Deployed on the same server as the API for simplicity.",
        consequence:"No network isolation between application tier and data tier. The API user has broad permissions because nobody set up least-privilege roles during the sprint. Root cause of T-102 impact severity.",
        alternative:"Separate VPC subnet for the database. Dedicated read-only and write-only API users with permission scoped to exactly the tables each operation needs." },
      { title:"Why Stripe?", icon:"💳",
        reason:"PCI-DSS compliance for card processing requires either becoming a PCI-certified merchant (expensive, slow) or using a tokenisation provider. Stripe was the correct call — it offloads card data scope entirely.",
        consequence:"Positive: PCI scope is dramatically reduced. TechMart never sees raw card numbers. This is documented as Assumption A1 and is a genuine security win from a pragmatic business decision.",
        alternative:"Building in-house card processing would be catastrophically worse. Stripe is the right call — but the team must understand the scope boundary and test it annually." },
      { title:"Why SendGrid?", icon:"📧",
        reason:"Transactional email is complex (deliverability, SPF/DKIM, rate limiting). SendGrid solved those problems instantly for $0/month on the free tier. Again: pragmatic team velocity decision.",
        consequence:"TechMart now sends customer PII (name, email, order contents) to a third-party service they don't control. Documented as Assumption A2. If SendGrid is breached, that data is exposed.",
        alternative:"Self-hosted email via SES with strict data minimisation — pass only the minimum fields needed (recipient address, template ID) and render content server-side rather than passing full order objects." },
    ],
    lesson:"The pattern: every architecture decision was optimised for speed-to-market. None were wrong choices for a pre-revenue startup. But none were evaluated for security implications. Threat modeling done at design time would have caught the localStorage JWT pattern and the raw SQL pattern in a single 2-hour session — before a line of code was written."
  },
  assets:[
    {name:"Customer PII (name, email, address)", classification:"Confidential",  impact:"GDPR fine up to 4% global revenue · identity theft"},
    {name:"Payment card data",                   classification:"PCI-Regulated", impact:"PCI-DSS breach · card-network ban · $500K+ fines"},
    {name:"Session tokens / JWTs",               classification:"Sensitive",      impact:"Account takeover · fraudulent orders"},
    {name:"Order history",                        classification:"Internal",       impact:"Business intelligence if exposed to competitors"},
  ],
  assumptions:[
    "Stripe handles card tokenisation — we never receive or store raw card numbers.",
    "SendGrid is trusted for email delivery — we do not control their security posture.",
    "The PostgreSQL server is NOT directly internet-accessible (private subnet).",
    "Customers are anonymous untrusted users until authenticated by the API.",
    "The React SPA runs in the customer's browser — we cannot trust its state.",
    "The Node.js API is the only authoritative source of truth for all business rules.",
  ],
  components:[
    {name:"Customer",     type:"external", zone:"Not in Control", score:0, desc:"End user — untrusted browser"},
    {name:"React SPA",    type:"process",  zone:"Minimal Trust",  score:1, desc:"Runs in customer browser"},
    {name:"Node.js API",  type:"process",  zone:"Standard",       score:3, desc:"Our application server"},
    {name:"PostgreSQL DB",type:"store",    zone:"Critical",       score:7, desc:"PII + orders — highest risk"},
    {name:"Stripe",       type:"external", zone:"Not in Control", score:0, desc:"3rd-party payment processor"},
    {name:"SendGrid",     type:"external", zone:"Not in Control", score:0, desc:"3rd-party email service"},
  ],
  flows:[
    {src:"Customer",     dst:"React SPA",    data:"HTTPS requests",   proto:"TLS 1.3"},
    {src:"React SPA",    dst:"Node.js API",  data:"API calls + JWTs", proto:"HTTPS"},
    {src:"Node.js API",  dst:"PostgreSQL DB",data:"SQL queries",      proto:"PostgreSQL"},
    {src:"PostgreSQL DB",dst:"Node.js API",  data:"Query results",    proto:"PostgreSQL"},
    {src:"Node.js API",  dst:"Stripe",       data:"Payment tokens",   proto:"HTTPS"},
    {src:"Node.js API",  dst:"SendGrid",     data:"Email content",    proto:"HTTPS"},
  ],
  boundaries:[
    {name:"Internet Boundary",   from:"Customer (Z0)",   to:"React SPA (Z1)",    risk:"All external input enters here — primary attack surface"},
    {name:"Application Boundary",from:"React SPA (Z1)",  to:"Node.js API (Z3)",  risk:"Client-side tampering becomes server-side impact"},
    {name:"Data Boundary",       from:"Node.js API (Z3)",to:"PostgreSQL DB (Z7)",risk:"Highest risk crossing — application to protected PII"},
  ],
  threats:[
    { id:"T-101", stride:"Spoofing",
      nodes:["Customer","React SPA","Node.js API"],
      flows:["Customer→React SPA","React SPA→Node.js API"],
      source:"An unauthenticated attacker (Customer, Z0)",
      action:"impersonate a legitimate user",
      asset:"the Node.js API session",
      method:"replaying a stolen JWT token obtained via XSS injection on the order page",
      impact:"gaining full account access to order history and saved delivery addresses",
      composed:"An unauthenticated attacker can impersonate a legitimate user by replaying a stolen JWT obtained via XSS, resulting in full account access to order history.",
      stride_rule:"Zone 0 → Node.js API node: Spoofing applies to all nodes reachable from an untrusted source.",
      component:"Node.js API", zone_from:"Not in Control", zone_to:"Standard",
      likelihood:"High", impact_rating:"High",
      explanation:"JWTs stored in localStorage are accessible via JavaScript. XSS on any page exfiltrates all localStorage tokens. Without short expiry + rotation, stolen tokens are valid for hours.",
      why_risk:"XSS is found by automated scanners in hours. Stolen JWT = indefinite account access until expiry. GDPR breach notification required within 72 hours.",
      controls_correct:["Short-lived JWTs (15 min) with refresh token rotation","HttpOnly + Secure cookies instead of localStorage","Content Security Policy header blocking inline scripts"],
      controls_wrong:["Longer sessions for better UX","Validate JWT format only (not signature)","Rate-limit the login endpoint only"],
      real_world:"2022 Optus (AU): 9.8M customers exposed. Unauthenticated API endpoint accepted any user ID. $1.5B remediation.",
      owasp:"A07:2021 — Identification & Authentication Failures" },
    { id:"T-102", stride:"Tampering",
      nodes:["React SPA","Node.js API","PostgreSQL DB"],
      flows:["React SPA→Node.js API","Node.js API→PostgreSQL DB"],
      source:"An authenticated customer (React SPA, Z1)",
      action:"modify database records without authorisation",
      asset:"the PostgreSQL DB order table (Z7)",
      method:"injecting SQL via an unsanitised order search parameter",
      impact:"exfiltrating the full customer PII table including names, addresses, and hashed passwords",
      composed:"An authenticated customer can modify database records by injecting SQL via an unsanitised search parameter, resulting in exfiltrating the full customer PII table.",
      stride_rule:"Zone 1 → Zone 3 → Zone 7 (score UP): Tampering applies to all upward-zone data flows.",
      component:"Node.js API → PostgreSQL DB", zone_from:"Standard", zone_to:"Critical",
      likelihood:"High", impact_rating:"Critical",
      explanation:"ORM misuse with raw template literals allows classic SQLi. The DB trusts queries from the API, which trusted input from Zone 0 — the chain of trust is broken.",
      why_risk:"SQLi is OWASP #1 for 15 years. sqlmap automates in minutes. Full PII dump = GDPR Art.83 max fine + PCI-DSS forensic audit.",
      controls_correct:["Parameterised queries exclusively — never interpolate user input into SQL","WAF with SQLi rule set (Cloudflare / AWS WAF)","Principle of least privilege: API DB user has no DROP/ALTER permissions"],
      controls_wrong:["Frontend input length validation (bypassed trivially)","Disabling SQL error messages (hides symptoms, not the vulnerability)","Manual escaping of special characters"],
      real_world:"2017 Equifax: 147M records via SQLi-class vulnerability. $575M FTC settlement. 78 days undetected.",
      owasp:"A03:2021 — Injection" },
    { id:"T-103", stride:"Information Disclosure",
      nodes:["PostgreSQL DB","Node.js API","Customer"],
      flows:["Node.js API→PostgreSQL DB","PostgreSQL DB→Node.js API"],
      source:"The Node.js API (Z3)",
      action:"expose sensitive database internals",
      asset:"any Customer browser (Z0)",
      method:"returning verbose PostgreSQL error messages in unhandled 500 responses",
      impact:"revealing table names, column structures, and query patterns enabling targeted SQL injection",
      composed:"The Node.js API exposes database internals via verbose PostgreSQL errors in 500 responses, enabling schema reconnaissance for targeted attacks.",
      stride_rule:"Zone 7 → Zone 3 → Zone 0 (score DOWN): Information Disclosure applies to downward-zone flows.",
      component:"PostgreSQL DB → Node.js API", zone_from:"Critical", zone_to:"Not in Control",
      likelihood:"Medium", impact_rating:"High",
      explanation:"Unhandled async exceptions bubble raw DB error objects through Express middleware. A malformed query returns full PostgreSQL error including table names and column types.",
      why_risk:"Schema knowledge reduces targeted attack time by ~90%. Converts a hard attack into an easy one.",
      controls_correct:["Global error handler: log full detail to SIEM, return only error ID to client","Structured logging (Winston/Pino) to CloudWatch — never to HTTP response","NODE_ENV=production disables verbose errors; enforce in deployment pipeline"],
      controls_wrong:["Custom 500 error page that still includes status code details","Email stack traces to developers","Debug flag disabled only in local development"],
      real_world:"2014 Target breach: verbose errors revealed DB schema used to craft the card-skimming payload. 40M payment cards stolen.",
      owasp:"A05:2021 — Security Misconfiguration" },
    { id:"T-104", stride:"Denial of Service",
      nodes:["Customer","React SPA","Node.js API","PostgreSQL DB"],
      flows:["Customer→React SPA","React SPA→Node.js API","Node.js API→PostgreSQL DB"],
      source:"An unauthenticated attacker (internet, Z0)",
      action:"exhaust the application's database connection pool",
      asset:"the Node.js API and PostgreSQL DB",
      method:"flooding the checkout endpoint with high request volume from a botnet",
      impact:"preventing all legitimate customers from completing purchases",
      composed:"An unauthenticated attacker can exhaust the database connection pool by flooding the checkout endpoint, preventing all legitimate customers from completing purchases.",
      stride_rule:"Zone 0 → any node: DoS applies whenever a Zone-0 entity can reach a node without enforced constraints.",
      component:"React SPA → Node.js API", zone_from:"Not in Control", zone_to:"Minimal Trust",
      likelihood:"High", impact_rating:"Medium",
      explanation:"No rate limiting on any endpoint. PostgreSQL pool: 20 connections (default). A botnet at 500 req/s exhausts the pool in under 1 second. DDoS-for-hire costs $20/hour.",
      why_risk:"For a $2M ARR startup, a 45-min checkout outage during peak hours = ~$3,500 lost revenue + customer trust damage.",
      controls_correct:["Cloudflare WAF with rate limiting (100 req/min per IP on /checkout)","Circuit breaker pattern: fail-fast when DB pool >80% utilised","PgBouncer connection pooling + auto-scaling"],
      controls_wrong:["Block specific IPs manually (defeated by IP rotation)","Increase DB pool to 200 (amplifies DB damage)","Alert after 5 minutes of sustained errors"],
      real_world:"2016 GitHub: 1.35 Tbps DDoS via Memcached amplification. Mitigated in 8 min by CDN. Without CDN: ~$2M in lost productivity.",
      owasp:"A05:2021 — Security Misconfiguration" },
    { id:"T-105", stride:"Elevation of Privilege",
      nodes:["React SPA","Node.js API","PostgreSQL DB"],
      flows:["React SPA→Node.js API","Node.js API→PostgreSQL DB"],
      source:"An authenticated customer (React SPA, Z1)",
      action:"gain administrative access to the Node.js API",
      asset:"all customer records in PostgreSQL DB",
      method:"modifying their JWT role claim using a JWT 'alg:none' attack",
      impact:"viewing and exfiltrating all 50,000 customer records, cancelling arbitrary orders",
      composed:"An authenticated customer can gain admin access by forging their JWT role claim via alg:none attack, resulting in access to all customer records.",
      stride_rule:"Node.js API is adjacent to React SPA (Zone 1): EoP applies to any node connected to a lower-trust zone.",
      component:"Node.js API", zone_from:"Minimal Trust", zone_to:"Standard",
      likelihood:"Medium", impact_rating:"Critical",
      explanation:"JWT 'none' algorithm: strip signature, set alg:none in header, change payload role to 'admin'. If the server validates structure but not the algorithm whitelist, it accepts the forged token.",
      why_risk:"Admin access to 50K-user DB: GDPR notification required, PCI-DSS audit, public disclosure. Technique is documented and tooled (jwt_tool).",
      controls_correct:["Fix allowed algorithms to RS256 only — explicitly reject 'none'","Server-side role check on EVERY protected endpoint — never trust JWT claims for authorisation","Separate admin API on internal VPC — not internet-facing"],
      controls_wrong:["Hide admin routes in the React UI (client-side is not a security control)","Rate-limit /admin/* endpoints","Validate JWT expiry timestamp only"],
      real_world:"2018 Uber: JWT none algorithm attack exposed admin panel to regular users. 57M users affected. $148M settlement.",
      owasp:"A01:2021 — Broken Access Control" },
  ],
  attackTree:{
    title:"Attack Tree: Steal Customer Payment Records",
    goal:"Exfiltrate customer PII / payment data from TechMart",
    paths:[
      {
        id:"pathA", label:"Path A — SQL Injection", priority:"HIGHEST", priorityCol:C.red,
        gateType:"OR",
        steps:[
          {id:"A1", label:"Craft malicious SQL payload", strideId:"T-102", strideType:"Tampering", difficulty:"Easy", detail:"sqlmap -u 'https://techmart.com/api/orders?id=1' automates this in minutes", component:"React SPA"},
          {id:"A2", label:"Submit via order search API", strideId:"T-102", strideType:"Tampering", difficulty:"Easy", detail:"Normal authenticated request — no WAF, no parameterised queries", component:"Node.js API"},
          {id:"A3", label:"Database returns full PII table", strideId:"T-102", strideType:"Tampering", difficulty:"Easy", detail:"API DB user has SELECT on all tables. sqlmap extracts 50K records.", component:"PostgreSQL DB"},
        ],
        mitigations:[
          {step:"A2", control:"Parameterised queries block SQL injection at source"},
          {step:"A2", control:"WAF SQLi rule set blocks before it reaches API"},
          {step:"A3", control:"Least privilege DB user: SELECT only on orders table owned by session user"},
        ]
      },
      {
        id:"pathB", label:"Path B — JWT Session Hijack", priority:"HIGH", priorityCol:C.amber,
        gateType:"AND",
        steps:[
          {id:"B1", label:"Inject XSS into order note field", strideId:"T-101", strideType:"Spoofing", difficulty:"Easy", detail:"No Content-Security-Policy. Any field renders HTML in order confirmation.", component:"React SPA"},
          {id:"B2", label:"Steal JWT from localStorage", strideId:"T-101", strideType:"Spoofing", difficulty:"Easy", detail:"document.cookie is HttpOnly-blocked, but localStorage is freely readable", component:"React SPA"},
          {id:"B3", label:"Replay JWT within 24h window", strideId:"T-101", strideType:"Spoofing", difficulty:"Easy", detail:"JWT expiry is 24h. No token rotation. Attacker has 24h to use it.", component:"Node.js API"},
        ],
        mitigations:[
          {step:"B1", control:"Content Security Policy: default-src 'self' eliminates XSS vector"},
          {step:"B2", control:"HttpOnly Secure cookies: localStorage completely bypassed"},
          {step:"B3", control:"15-min JWT expiry + refresh token rotation: replayed token rejected"},
        ]
      },
      {
        id:"pathC", label:"Path C — Privilege Escalation", priority:"MEDIUM", priorityCol:C.green,
        gateType:"OR",
        steps:[
          {id:"C1", label:"Forge JWT with role:admin", strideId:"T-105", strideType:"Elevation of Privilege", difficulty:"Medium", detail:"jwt_tool.py -t <token> -S none -pc role -pv admin", component:"React SPA"},
          {id:"C2", label:"Submit to admin endpoint", strideId:"T-105", strideType:"Elevation of Privilege", difficulty:"Easy", detail:"No server-side role guard. UI hides routes but API accepts any token.", component:"Node.js API"},
          {id:"C3", label:"Access all 50K customer records", strideId:"T-105", strideType:"Elevation of Privilege", difficulty:"Easy", detail:"Admin API has unrestricted SELECT on customer table.", component:"PostgreSQL DB"},
        ],
        mitigations:[
          {step:"C1", control:"Algorithm whitelist: RS256 only, reject 'none' — forged token invalid"},
          {step:"C2", control:"Server-side role lookup from DB on every request — JWT role claim ignored"},
          {step:"C3", control:"Admin API on internal VPC only — not internet-accessible"},
        ]
      },
    ],
  },
  q4_validation:{
    checklist:[
      "Does every identified threat have at least one linked mitigation?",
      "Have we covered all 6 STRIDE categories — or documented why any don't apply?",
      "Are highest-impact threats (T-102, T-105) prioritised for immediate remediation?",
      "Have we tested that mitigations are implemented — not just planned?",
      "Would a penetration tester surface anything our threat model missed?",
      "Are our documented assumptions still valid? (Check quarterly.)",
    ],
    gap:"Repudiation — partially covered: Node.js API has no structured audit log for authentication events or order mutations. Recommendation: add append-only event log. Documented gap accepted for v1.",
  },
},
"2":{
  id:"2", name:"CloudBank Mobile Banking", subtitle:"Microservices Architecture",
  level:"INTERMEDIATE", levelColor:C.blue, duration:"90 min",
  access:"CODE", unlockCode:"MICRO2025",
  compliance:["PCI-DSS","SOC 2","GLBA"],
  businessContext:"Regional bank · 500K customers · $2B AUM",
  description:"Mobile banking app (iOS/Android). API Gateway routes to User Service (auth) and Payment Service (transfers). Two separate databases. mTLS between internal services.",
  archRationale:{
    summary:"CloudBank migrated from a monolith to microservices over 18 months. Each service was extracted by a different team. The security model was designed for the monolith — it was never fully re-evaluated for the distributed system that replaced it.",
    decisions:[
      {title:"Why microservices?",icon:"🔧",reason:"Monolith became a deployment bottleneck. 40 engineers couldn't ship independently. Services were extracted by team boundary — not by security boundary.",consequence:"Each service now makes trust decisions independently. The monolith had one auth check. Now there are 4 services each making their own — and they don't all agree on what 'authenticated' means.",alternative:"Service mesh with centralised policy enforcement (Istio/OPA) would enforce consistent auth decisions across all services without trusting each team to get it right."},
      {title:"Why API Gateway?",icon:"🌐",reason:"Single internet-facing entry point. JWT validation at the gateway reduces duplicated auth logic in each service.",consequence:"Services trust the Gateway's validation. If a token passes Gateway validation, services assume it's legitimate — they don't re-validate business logic (amount bounds, account ownership).",alternative:"Gateway handles identity. Each service handles authorisation for its own resources. These are different concerns and must not be conflated."},
      {title:"Why mTLS internally?",icon:"🔐",reason:"Correct decision — network-level encryption between services prevents eavesdropping on the internal network.",consequence:"mTLS proves which service is calling. It does NOT prove the data payload is valid. Services still trust request body fields without integrity verification.",alternative:"mTLS + HMAC-signed payloads. Transport security ≠ data integrity. Both are needed."},
    ],
    lesson:"The microservices migration decentralised trust decisions without centralising policy enforcement. Every service team solved auth differently. The threat model exposes where those inconsistencies create exploitable gaps."
  },
  assets:[
    {name:"Customer credentials",classification:"Confidential",impact:"Account takeover · GLBA violation"},
    {name:"Financial transaction records",classification:"PCI-Regulated",impact:"Regulatory fines · fraud liability"},
    {name:"OAuth tokens",classification:"Sensitive",impact:"Unauthorised transfers · session hijacking"},
  ],
  assumptions:[
    "Mobile app binary is not trusted — treat as a hostile environment.",
    "mTLS is configured correctly between ALL internal services.",
    "API Gateway is the single internet-facing entry point.",
    "All authorisation is performed by individual services — not the Gateway.",
  ],
  components:[
    {name:"Mobile App",     type:"external",zone:"Not in Control",score:0,desc:"iOS/Android — device not controlled"},
    {name:"API Gateway",    type:"process", zone:"Minimal Trust", score:1,desc:"AWS API GW — JWT validation entry"},
    {name:"User Service",   type:"process", zone:"Elevated",      score:5,desc:"Auth + identity — ECS Fargate"},
    {name:"Payment Service",type:"process", zone:"Elevated",      score:5,desc:"Financial transfers — ECS Fargate"},
    {name:"User DB",        type:"store",   zone:"Critical",      score:7,desc:"DynamoDB — credentials + profiles"},
    {name:"Transaction DB", type:"store",   zone:"Critical",      score:8,desc:"Aurora — financial ledger"},
  ],
  flows:[
    {src:"Mobile App",    dst:"API Gateway",   data:"HTTPS requests", proto:"TLS 1.3"},
    {src:"API Gateway",   dst:"User Service",  data:"Auth requests",  proto:"HTTP/2 mTLS"},
    {src:"API Gateway",   dst:"Payment Service",data:"Payment requests",proto:"HTTP/2 mTLS"},
    {src:"User Service",  dst:"User DB",       data:"User data",      proto:"DynamoDB SDK"},
    {src:"Payment Service",dst:"Transaction DB",data:"Transactions",  proto:"PostgreSQL"},
  ],
  boundaries:[
    {name:"Client Boundary",      from:"Mobile App (Z0)",  to:"API Gateway (Z1)",risk:"Mobile device untrusted — primary entry for spoofing + DoS"},
    {name:"Service Mesh Boundary",from:"API Gateway (Z1)", to:"Services (Z5)",   risk:"mTLS required — misconfiguration = service impersonation"},
    {name:"Data Boundary",        from:"Services (Z5)",    to:"DBs (Z7/Z8)",     risk:"Financial data — highest protection requirement"},
  ],
  threats:[
    {id:"T-201",stride:"Spoofing",nodes:["Mobile App","API Gateway"],flows:["Mobile App→API Gateway"],source:"Mobile App (Z0)",action:"impersonate a legitimate user",asset:"API Gateway session",method:"presenting a stolen OAuth token without device binding",impact:"full account access without possessing the registered device",composed:"A mobile attacker can impersonate a legitimate user by presenting a stolen OAuth token, resulting in full account access.",stride_rule:"Zone 0 → API Gateway node: Spoofing applies.",component:"API Gateway",zone_from:"Not in Control",zone_to:"Minimal Trust",likelihood:"High",impact_rating:"High",explanation:"OAuth tokens without device binding work from any device. Once stolen (malware, debug logs, MITM), they grant full access.",why_risk:"Banking app: stolen token = full account + transfer capability. GLBA violation.",controls_correct:["OAuth token binding to device certificate","Certificate pinning in mobile app","Refresh token rotation with single-use guarantee"],controls_wrong:["Long-lived tokens for UX","Trust mobile app version string","IP throttling only"],real_world:"2020 Dave banking app: 7.5M credentials exposed. OAuth without device binding.",owasp:"A07:2021 — Auth Failures"},
    {id:"T-202",stride:"Tampering",nodes:["API Gateway","Payment Service","Transaction DB"],flows:["API Gateway→Payment Service","Payment Service→Transaction DB"],source:"API Gateway (Z1)",action:"forward tampered transaction amounts",asset:"Payment Service (Z5)",method:"modifying the amount field after JWT validation — Payment Service trusts upstream",impact:"processing unauthorised transfers of arbitrary amounts",composed:"An attacker can tamper with transaction amounts forwarded by the API Gateway because Payment Service trusts upstream without re-validating amounts.",stride_rule:"Zone 1 → Zone 5 (UP): Tampering applies.",component:"API Gateway → Payment Service",zone_from:"Minimal Trust",zone_to:"Elevated",likelihood:"High",impact_rating:"Critical",explanation:"JWT validates identity but not transaction integrity. Amount field is trusted from upstream without Payment Service re-validation.",why_risk:"Direct financial loss. GLBA liability.",controls_correct:["Re-validate ALL business logic in Payment Service — never trust upstream fields","HMAC-signed transaction payloads","Idempotency keys with amount binding"],controls_wrong:["Trust API Gateway validation","Client-side amount validation","Transaction logging only"],real_world:"2016 Bangladesh Bank: $81M stolen via SWIFT parameter tampering between systems that trusted each other.",owasp:"A04:2021 — Insecure Design"},
    {id:"T-203",stride:"Repudiation",nodes:["Payment Service","Transaction DB"],flows:["Payment Service→Transaction DB"],source:"Internal actor",action:"deny performing a transaction",asset:"Transaction DB audit trail",method:"deleting or modifying transaction log entries in the same mutable database",impact:"inability to prove financial actions in disputes",composed:"An internal actor can deny performing transactions by modifying mutable audit logs, resulting in inability to resolve financial disputes.",stride_rule:"Spoofing + Tampering both apply to Payment Service → Repudiation applies.",component:"Payment Service",zone_from:"Elevated",zone_to:"Critical",likelihood:"Medium",impact_rating:"High",explanation:"Mutable logs = no audit trail. PostgreSQL DELETE is permanent without CDC. GLBA requires 7-year retention.",why_risk:"Medium likelihood (insider). Regulatory fines + disputes with no evidence = bank loses by default.",controls_correct:["Append-only audit log (QLDB or S3 with Object Lock)","CDC with Debezium capturing all DB mutations","Distributed tracing correlated to transaction IDs"],controls_wrong:["Regular database backups","Application-level logging only","Disable DELETE for app user"],real_world:"2023 SVB collapse: gaps in audit trails delayed FDIC resolution by weeks.",owasp:"A09:2021 — Security Logging Failures"},
    {id:"T-204",stride:"Information Disclosure",nodes:["Transaction DB","Payment Service","API Gateway"],flows:["Payment Service→Transaction DB","Transaction DB→Payment Service"],source:"Transaction DB (Z8)",action:"expose complete financial history beyond what is needed",asset:"API Gateway cache (Z1)",method:"Payment Service returning full SELECT * records where only balance is requested",impact:"years of transaction history cached at Zone 1",composed:"Transaction DB exposes complete financial history via over-fetched data cached at API Gateway, resulting in mass disclosure if the Gateway is compromised.",stride_rule:"Zone 8 → Zone 5 → Zone 1 (DOWN): Information Disclosure applies.",component:"Transaction DB → Payment Service",zone_from:"Critical",zone_to:"Minimal Trust",likelihood:"Medium",impact_rating:"High",explanation:"SELECT * returns 5 years of transactions cached at Zone 1. Gateway compromise = years of financial history exposed.",why_risk:"GLBA data minimisation violation.",controls_correct:["Return only required fields per endpoint","Cache-Control: no-store for all financial data","Response field whitelist at API Gateway"],controls_wrong:["Encrypt cache contents","Mask last 4 digits in UI only","Reduce cache TTL to 1 hour"],real_world:"2019 Capital One: WAF misconfiguration returned 100M customer records. Over-permissive IAM + cached data.",owasp:"A02:2021 — Cryptographic Failures"},
    {id:"T-205",stride:"Elevation of Privilege",nodes:["API Gateway","User Service","User DB"],flows:["API Gateway→User Service","User Service→User DB"],source:"API Gateway (Z1)",action:"grant admin access to a regular user",asset:"User Service (Z5)",method:"User Service trusting JWT role claim without server-side validation",impact:"regular customer gaining admin access to all 500K accounts",composed:"A regular customer can gain admin access to User Service by forging the JWT role claim, resulting in access to all 500K accounts.",stride_rule:"User Service adjacent to API Gateway (Z1) → EoP applies.",component:"User Service",zone_from:"Minimal Trust",zone_to:"Elevated",likelihood:"Medium",impact_rating:"Critical",explanation:"JWT none algorithm attack. User Service validates structure, not signature algorithm. Role decided by JWT claim, not server-side lookup.",why_risk:"Admin role = view all 500K accounts, initiate any transfer, disable MFA. GLBA + SOC 2 violation.",controls_correct:["Verify JWT signature with fixed algorithm (RS256 — reject 'none')","Server-side role lookup from User DB — never trust JWT claims for authorisation","Separate admin endpoints behind VPC, not internet-accessible"],controls_wrong:["Rely on API Gateway JWT validation alone","Trust role field in JWT payload","Validate expiry only"],real_world:"2018 Uber: JWT none attack → admin panel. 57M users. $148M settlement.",owasp:"A01:2021 — Broken Access Control"},
  ],
  attackTree:{
    title:"Attack Tree: Execute Unauthorised Bank Transfer",
    goal:"Transfer funds from victim account without authorisation",
    paths:[
      {id:"pathA",label:"Path A — Credential + MFA Bypass",priority:"HIGH",priorityCol:C.amber,gateType:"AND",
       steps:[
         {id:"A1",label:"Steal credentials via phishing",strideId:"T-201",strideType:"Spoofing",difficulty:"Easy",detail:"Fake CloudBank login page captures username + password",component:"Mobile App"},
         {id:"A2",label:"SIM-swap to bypass SMS MFA",strideId:"T-201",strideType:"Spoofing",difficulty:"Medium",detail:"Social engineering mobile carrier — takes 1-2 days",component:"API Gateway"},
       ],
       mitigations:[
         {step:"A1",control:"FIDO2 hardware key or app-based MFA: phishing-resistant"},
         {step:"A2",control:"App-based TOTP or push auth: SIM-swap has no effect"},
       ]
      },
      {id:"pathB",label:"Path B — Token Theft",priority:"MEDIUM",priorityCol:C.green,gateType:"OR",
       steps:[
         {id:"B1",label:"MITM on device (cert pinning bypass)",strideId:"T-201",strideType:"Spoofing",difficulty:"Hard",detail:"Root device + install CA cert. Difficult but possible.",component:"Mobile App"},
         {id:"B2",label:"Steal refresh token from app storage",strideId:"T-201",strideType:"Spoofing",difficulty:"Medium",detail:"Insecure storage on rooted device or backup extraction",component:"Mobile App"},
       ],
       mitigations:[
         {step:"B1",control:"Certificate pinning: MITM fails even on rooted device"},
         {step:"B2",control:"Encrypted keystore + token binding to device certificate"},
       ]
      },
      {id:"pathC",label:"Path C — Amount Tampering",priority:"HIGHEST",priorityCol:C.red,gateType:"OR",
       steps:[
         {id:"C1",label:"Intercept transfer request",strideId:"T-202",strideType:"Tampering",difficulty:"Medium",detail:"Proxy tool (Burp Suite) between app and API Gateway",component:"Mobile App"},
         {id:"C2",label:"Modify amount field after JWT validation",strideId:"T-202",strideType:"Tampering",difficulty:"Easy",detail:"Payment Service trusts upstream — no re-validation of amount bounds",component:"Payment Service"},
       ],
       mitigations:[
         {step:"C1",control:"HMAC-signed request body: modification detectable at Payment Service"},
         {step:"C2",control:"Payment Service re-validates amount against account limits and session"},
       ]
      },
    ],
  },
  q4_validation:{
    checklist:[
      "Are all financial flows protected by both mTLS (transport) and HMAC (payload integrity)?",
      "Is the audit log genuinely append-only and tested for tamper resistance?",
      "Are token binding + cert pinning implemented in both iOS and Android builds?",
      "Has the Payment Service been tested to reject tampered amount fields?",
      "Are GLBA 7-year retention requirements met for the audit log?",
    ],
    gap:"Denial of Service on Payment Service not fully analysed — should be addressed in v2 given the impact of payment unavailability.",
  },
},
"3":{
  id:"3", name:"DataInsight Analytics", subtitle:"Multi-Tenant SaaS Platform",
  level:"ADVANCED", levelColor:C.amber, duration:"90 min",
  access:"CODE", unlockCode:"TENANT2025",
  compliance:["SOC 2 Type II","ISO 27001","GDPR"],
  businessContext:"B2B SaaS · 500 enterprise tenants · $20M ARR",
  description:"Multi-tenant analytics platform. Tenants upload data via API Gateway → shared Kafka → Query Service → shared Redshift data warehouse with row-level partitioning.",
  archRationale:{
    summary:"DataInsight was built as a single-tenant product and retrofitted for multi-tenancy as the customer base grew. The isolation model was added as an afterthought — bolted on top of a shared-everything infrastructure.",
    decisions:[
      {title:"Why shared infrastructure?",icon:"🏗",reason:"Cost. Running 500 separate database clusters would cost $500K/month. Shared Redshift with row-level security costs $15K/month.",consequence:"All 500 tenants' data sits in the same database. A single misconfiguration exposes all of them simultaneously. The blast radius of any isolation failure is 100% of customers.",alternative:"Separate schemas per tenant (middle ground): still shared DB, but schema-level isolation gives a meaningful additional barrier. Full database-per-tenant isolation for top-tier customers."},
      {title:"Why application-layer isolation?",icon:"🔒",reason:"The original single-tenant app used user_id for filtering. Multi-tenancy added tenant_id by the same pattern — a WHERE clause in application code.",consequence:"Isolation depends entirely on the application never making a mistake. One missing WHERE clause, one cached query result without a tenant_id, exposes cross-tenant data.",alternative:"Database-layer Row Level Security enforced by PostgreSQL/Redshift itself. Even a buggy query gets filtered at the DB layer. Defence-in-depth for isolation."},
    ],
    lesson:"Multi-tenant isolation is not a feature to add later — it is a foundational architectural constraint. Retrofitting it is expensive and leaves gaps. The threat model shows exactly where those gaps are."
  },
  assets:[
    {name:"Tenant analytics data",classification:"Confidential",impact:"Contractual breach · competitive intelligence exposure"},
    {name:"Tenant credentials",classification:"Sensitive",impact:"Account takeover · cross-tenant access"},
    {name:"Redshift schema",classification:"Internal",impact:"Enables targeted attacks if exposed"},
  ],
  assumptions:[
    "Tenant isolation is enforced at the APPLICATION layer via tenant_id from JWT — NOT at the database layer.",
    "Kafka topics are SHARED across all tenants with logical partitioning only.",
    "The Query Service is a shared process — no per-tenant process isolation.",
    "All tenant_ids are derived from the authenticated JWT, never from request parameters.",
  ],
  components:[
    {name:"Tenant Browser",type:"external",zone:"Not in Control",score:0,desc:"Tenant user — untrusted browser"},
    {name:"API Gateway",   type:"process", zone:"Minimal Trust", score:2,desc:"Kong — routing + JWT validation"},
    {name:"Ingestion Svc", type:"process", zone:"Standard",      score:3,desc:"Data ingestion — shared service"},
    {name:"Query Service", type:"process", zone:"Standard",      score:3,desc:"Analytics query engine — shared"},
    {name:"Kafka",         type:"store",   zone:"Elevated",      score:5,desc:"MSK — shared topics"},
    {name:"Data Warehouse",type:"store",   zone:"Critical",      score:8,desc:"Redshift — ALL tenant data"},
  ],
  flows:[
    {src:"Tenant Browser",dst:"API Gateway",  data:"Tenant requests",proto:"HTTPS"},
    {src:"API Gateway",   dst:"Ingestion Svc",data:"Data uploads",   proto:"HTTPS"},
    {src:"Ingestion Svc", dst:"Kafka",        data:"Events",         proto:"Kafka"},
    {src:"Kafka",         dst:"Query Service",data:"Stream data",    proto:"Consumer"},
    {src:"Query Service", dst:"Data Warehouse",data:"SQL queries",   proto:"JDBC"},
    {src:"Data Warehouse",dst:"Query Service",data:"Query results",  proto:"JDBC"},
  ],
  boundaries:[
    {name:"Tenant Boundary",    from:"Browser (Z0)",      to:"API Gateway (Z2)",   risk:"Tenant isolation begins here — JWT must encode tenant_id reliably"},
    {name:"Isolation Boundary", from:"Services (Z2-3)",   to:"Shared infra",       risk:"All operations MUST propagate tenant_id or isolation breaks"},
    {name:"Shared Data Boundary",from:"Query Service (Z3)",to:"Redshift (Z8)",     risk:"Single warehouse holds ALL tenants — one bug = mass leak"},
  ],
  threats:[
    {id:"T-301",stride:"Elevation of Privilege",nodes:["Tenant Browser","API Gateway","Query Service","Data Warehouse"],flows:["Tenant Browser→API Gateway","API Gateway→Query Service","Query Service→Data Warehouse"],source:"Tenant A user (Z0)",action:"access Tenant B's analytics data",asset:"Query Service + Data Warehouse",method:"forging tenant_id parameter in query request",impact:"exfiltrating all competitor analytics data",composed:"Tenant A can access Tenant B's data by forging the tenant_id in the query parameter, resulting in exfiltrating all competitor analytics data.",stride_rule:"EoP applies to Query Service adjacent to Z0 via chain.",component:"Query Service",zone_from:"Not in Control",zone_to:"Critical",likelihood:"High",impact_rating:"Critical",explanation:"Query Service trusts client-supplied tenant_id instead of the JWT claim.",why_risk:"All 500 enterprise tenants exposed. SOC 2 Type II violation = immediate contract termination.",controls_correct:["Always derive tenant_id from JWT — never from request parameters","Redshift Row-Level Security enforced on every query","Automated cross-tenant boundary tests in CI/CD"],controls_wrong:["Log tenant_id from requests","Validate tenant_id format (UUID check)","Rate limit per tenant"],real_world:"2019 Capital One: IAM misconfiguration exposed 100M+ records across account boundaries.",owasp:"A01:2021 — Broken Access Control"},
    {id:"T-302",stride:"Information Disclosure",nodes:["Data Warehouse","Query Service","API Gateway"],flows:["Query Service→Data Warehouse","Data Warehouse→Query Service"],source:"Data Warehouse (Z8)",action:"expose cross-tenant data",asset:"API Gateway cache (Z2)",method:"Query Service caching full results keyed only by query hash (not tenant_id + hash)",impact:"Tenant A receiving Tenant B's analytics data from cache collision",composed:"Shared cache keyed without tenant_id causes cross-tenant data exposure when query hashes collide.",stride_rule:"Zone 8 → Zone 3 → Zone 2 (DOWN): Information Disclosure applies.",component:"Data Warehouse → Query Service",zone_from:"Critical",zone_to:"Minimal Trust",likelihood:"Medium",impact_rating:"Critical",explanation:"Cache key = hash(query) only. Similar queries from different tenants = same hash = cross-tenant data returned.",why_risk:"Critical: analytics data IS the product. B2B data leak = mass churn + litigation.",controls_correct:["Cache key MUST include tenant_id: hash(tenant_id + query)","Redis keyspace isolation per tenant","RLS at DB level as defence-in-depth"],controls_wrong:["Encrypt cache","Clear cache hourly","SHA-256 query hash only"],real_world:"2017 Cloudflare Cloudbleed: shared buffer without tenant isolation exposed 3.4M websites.",owasp:"A02:2021 — Cryptographic Failures"},
    {id:"T-303",stride:"Tampering",nodes:["Ingestion Svc","Kafka"],flows:["Ingestion Svc→Kafka"],source:"Ingestion Service (Z3)",action:"write events to wrong tenant partition",asset:"Kafka shared topics",method:"Kafka ACLs not enforced per tenant — any producer can write any tenant_id",impact:"corrupting another tenant's analytics pipeline",composed:"Ingestion Service can write events with any tenant_id to shared Kafka topics due to missing ACLs, resulting in analytics data poisoning.",stride_rule:"Zone 3 → Zone 5 (UP): Tampering applies.",component:"Ingestion Svc → Kafka",zone_from:"Standard",zone_to:"Elevated",likelihood:"Medium",impact_rating:"High",explanation:"Kafka ACLs not per-tenant. Any authenticated producer writes any partition.",why_risk:"Data integrity poisoning. ISO 27001 A.12 violation.",controls_correct:["Kafka ACLs: each tenant writes only their partition prefix","Ingestion Service enforces tenant_id from JWT on all Kafka produce calls","Schema registry with tenant namespace isolation"],controls_wrong:["Trust tenant_id from Kafka message body","Rate limit producers","Encrypt Kafka topics"],real_world:"2020 Shopify insider threat: shared pipeline without per-tenant access controls exposed merchant transaction data.",owasp:"A04:2021 — Insecure Design"},
    {id:"T-304",stride:"Denial of Service",nodes:["Tenant Browser","API Gateway"],flows:["Tenant Browser→API Gateway"],source:"Tenant A (Z0)",action:"exhaust shared API Gateway resources",asset:"all 499 other tenants simultaneously",method:"bulk upload script generating 10,000 requests/minute with no per-tenant rate limit",impact:"503 errors for all 499 other tenants — simultaneous SLA violation",composed:"One tenant can exhaust shared API Gateway resources, resulting in service unavailability for all other tenants.",stride_rule:"Zone 0 → API Gateway: DoS applies.",component:"API Gateway",zone_from:"Not in Control",zone_to:"Minimal Trust",likelihood:"High",impact_rating:"High",explanation:"No per-tenant rate limiting. Global pool shared across 500 tenants.",why_risk:"499 tenants affected = mass SLA violation. SOC 2 A1.1 failure.",controls_correct:["Per-tenant rate limiting at API Gateway (Kong rate-limit plugin)","Tenant quota enforcement with circuit breaker","Separate async queue per tenant for bulk uploads"],controls_wrong:["Global rate limit across all tenants","Increase total connection pool","Alert on 503s after 5 minutes"],real_world:"2021 Fastly outage: single misconfigured customer triggered global CDN outage.",owasp:"A05:2021 — Security Misconfiguration"},
    {id:"T-305",stride:"Repudiation",nodes:["Query Service","Data Warehouse"],flows:["Query Service→Data Warehouse"],source:"Tenant user",action:"deny running a query that accessed sensitive data",asset:"Query Service audit trail",method:"audit logs recording only tenant_id, not individual user_id",impact:"inability to attribute queries to specific users for SOC 2 audit",composed:"A tenant user can deny running specific queries because audit logs record tenant_id but not user_id, resulting in SOC 2 audit failure.",stride_rule:"Spoofing + Tampering both apply to Query Service → Repudiation applies.",component:"Query Service",zone_from:"Standard",zone_to:"Critical",likelihood:"Low",impact_rating:"High",explanation:"SOC 2 requires individual user accountability. Tenant-level logs fail.",why_risk:"SOC 2 Type II audit failure on CC7. Losing certification = losing all enterprise customers.",controls_correct:["Audit log: tenant_id + user_id + query + timestamp + result_row_count","Immutable log store (CloudWatch Logs with no-delete policy)","Anomaly detection on cross-tenant query patterns"],controls_wrong:["Log at tenant level only","30-day log retention","Query frequency monitoring only"],real_world:"2023 MOVEit: missing audit trails made incident response 3× slower.",owasp:"A09:2021 — Security Logging Failures"},
  ],
  attackTree:{
    title:"Attack Tree: Cross-Tenant Data Exfiltration",
    goal:"Access competitor tenant's proprietary analytics data",
    paths:[
      {id:"pathA",label:"Path A — Query Parameter Forgery",priority:"HIGHEST",priorityCol:C.red,gateType:"OR",
       steps:[
         {id:"A1",label:"Authenticate as Tenant A",strideId:"T-301",strideType:"Elevation of Privilege",difficulty:"Easy",detail:"Normal login — attacker is a legitimate but malicious tenant",component:"API Gateway"},
         {id:"A2",label:"Change tenant_id in query parameter",strideId:"T-301",strideType:"Elevation of Privilege",difficulty:"Easy",detail:"Query Service reads tenant_id from request param, not JWT",component:"Query Service"},
         {id:"A3",label:"Receive Tenant B's analytics data",strideId:"T-301",strideType:"Elevation of Privilege",difficulty:"Easy",detail:"No DB-level RLS — all data returned",component:"Data Warehouse"},
       ],
       mitigations:[{step:"A2",control:"JWT-derived tenant_id only — request param completely ignored"},{step:"A3",control:"Redshift RLS: enforced even if application logic is wrong"}]
      },
      {id:"pathB",label:"Path B — Cache Poisoning",priority:"HIGH",priorityCol:C.amber,gateType:"OR",
       steps:[
         {id:"B1",label:"Identify a query similar to Tenant B's",strideId:"T-302",strideType:"Information Disclosure",difficulty:"Medium",detail:"Trial and error or schema reconnaissance via error messages"},
         {id:"B2",label:"Submit identical query — hit Tenant B's cache entry",strideId:"T-302",strideType:"Information Disclosure",difficulty:"Easy",detail:"Cache key = query hash only. Collision returns Tenant B's results.",component:"Query Service"},
       ],
       mitigations:[{step:"B2",control:"Cache key = hash(tenant_id + query): collision impossible across tenants"}]
      },
    ],
  },
  q4_validation:{
    checklist:[
      "Is every Redshift query tested to enforce RLS with the correct tenant_id?",
      "Is the cache key verified to include tenant_id in integration tests?",
      "Are Kafka ACLs validated in the deployment pipeline?",
      "Can a SOC 2 auditor trace every query to a specific user (not just tenant)?",
      "Is cross-tenant isolation tested by the security team quarterly?",
    ],
    gap:"Encryption-at-rest for Redshift not fully documented here — covered under separate data classification policy but should be linked to this model.",
  },
},
"4":{
  id:"4", name:"HealthMonitor Connected Care", subtitle:"IoT + Healthcare · Life-Critical",
  level:"EXPERT", levelColor:C.purple, duration:"90 min",
  access:"CODE", unlockCode:"HEALTH2025",
  compliance:["HIPAA","FDA 21 CFR Part 11","HITECH","IEC 62304"],
  businessContext:"FDA-registered device · 10K patients · Life-critical glucose alerts",
  description:"Continuous glucose monitors send readings via BLE to IoT gateway at patient homes. Gateway forwards via MQTT/TLS to cloud. Alert Service dispatches critical alerts. Patient data in HIPAA-regulated DB. Legacy EHR integration via HL7v2.",
  archRationale:{
    summary:"HealthMonitor's architecture reflects two competing pressures: FDA regulatory requirements demand auditability and integrity, while the IoT hardware constraints (BLE, battery, compute) limit what security controls are physically possible to deploy.",
    decisions:[
      {title:"Why BLE for device comms?",icon:"📡",reason:"BLE is the only practical wireless standard for a small wearable sensor. It supports the data rate needed for continuous glucose readings and is power-efficient enough for a 7-day battery life.",consequence:"BLE has no native message authentication code (MAC) by default. Without MAC, packets can be captured and replayed with no detection. The device can't tell the difference between a real reading now and a replayed reading from yesterday.",alternative:"BLE with an application-layer MAC on every packet. Adds 32 bytes per message — acceptable overhead. Timestamp + sequence number enforces freshness."},
      {title:"Why MQTT for gateway-to-cloud?",icon:"☁",reason:"MQTT is the IoT standard for constrained networks. Low overhead, pub/sub model, well-supported by cloud IoT services.",consequence:"Default MQTT has no client authentication. Any device can connect to the MQTT broker and publish as any patient. The broker accepts messages from the IoT gateway — but doesn't verify which gateway.",alternative:"MQTT with X.509 client certificates provisioned at manufacturing. Each device gets a unique certificate burned in at the factory. Certificate = device identity."},
      {title:"Why legacy HL7v2 / MLLP?",icon:"🏥",reason:"Hospital EHR systems built in the 1990s and 2000s use HL7v2 over MLLP. This is not a choice — it is a constraint of every hospital integration. FHIR R4 is the modern standard but adoption is slow.",consequence:"MLLP has no native encryption. All patient PHI transmitted over hospital networks in plaintext. Any device on the hospital network can read it with a packet capture tool.",alternative:"TLS wrapper for MLLP (non-standard but achievable). Long-term migration to FHIR R4 which has native TLS."},
    ],
    lesson:"Life-critical systems require the highest security — but also face the greatest hardware constraints. Every architecture decision here involves a trade-off between security, battery life, hardware cost, and regulatory timeline. The threat model makes those trade-offs explicit and documented."
  },
  assets:[
    {name:"Patient glucose readings",classification:"PHI",impact:"HIPAA violation · patient safety if tampered"},
    {name:"Critical alert pipeline",classification:"Safety-Critical",impact:"Patient death or harm if delayed or suppressed"},
    {name:"Patient PHI (full record)",classification:"PHI",impact:"HIPAA fine $100–$50K per violation"},
  ],
  assumptions:[
    "The CGM device is physically accessible to the patient AND potentially hostile parties in the home.",
    "BLE is the ONLY channel between CGM and gateway — no backup transmission path.",
    "Alert Service must deliver alerts within 60 seconds of threshold crossing — this is a SAFETY requirement.",
    "The Legacy EHR is NOT controlled by our organisation.",
  ],
  components:[
    {name:"CGM Device",    type:"external",zone:"Not in Control",score:0,desc:"At patient home — physical access possible"},
    {name:"IoT Gateway",   type:"process", zone:"Minimal Trust", score:1,desc:"Edge device at patient home"},
    {name:"Device Data Svc",type:"process",zone:"Standard",      score:4,desc:"Cloud telemetry processor"},
    {name:"Alert Service", type:"process", zone:"Max Security",  score:9,desc:"SAFETY-CRITICAL alert dispatch"},
    {name:"Patient DB",    type:"store",   zone:"Max Security",  score:9,desc:"Aurora — PHI — HIPAA regulated"},
    {name:"Legacy EHR",    type:"external",zone:"Not in Control",score:0,desc:"Hospital EHR — not our system"},
  ],
  flows:[
    {src:"CGM Device",    dst:"IoT Gateway",    data:"Glucose readings",proto:"BLE"},
    {src:"IoT Gateway",   dst:"Device Data Svc",data:"Vital telemetry", proto:"MQTT/TLS"},
    {src:"Device Data Svc",dst:"Alert Service", data:"Alert events",    proto:"HTTP/2"},
    {src:"Alert Service", dst:"Patient DB",     data:"PHI records",     proto:"SQL/TLS"},
    {src:"Device Data Svc",dst:"Legacy EHR",    data:"HL7 messages",    proto:"MLLP"},
  ],
  boundaries:[
    {name:"Physical Device Boundary", from:"CGM (Z0)",            to:"IoT Gateway (Z1)",    risk:"Physical tampering at patient home — replay and injection attacks"},
    {name:"Edge-to-Cloud Boundary",   from:"IoT Gateway (Z1)",    to:"Device Data Svc (Z4)",risk:"Replay attacks on telemetry — no timestamp/MAC in default BLE"},
    {name:"Safety-Critical Boundary", from:"Device Data Svc (Z4)",to:"Alert Service (Z9)",  risk:"Any delay or suppression here = patient safety incident"},
  ],
  threats:[
    {id:"T-401",stride:"Tampering",nodes:["CGM Device","IoT Gateway","Device Data Svc"],flows:["CGM Device→IoT Gateway","IoT Gateway→Device Data Svc"],source:"Attacker with physical access to patient home",action:"falsify current glucose readings",asset:"IoT Gateway → Device Data Svc",method:"replaying captured BLE glucose readings from a safe-range period during a hypoglycaemic episode",impact:"suppressing the critical low-glucose alert — patient goes into hypoglycaemic coma undetected",composed:"A physically present attacker can falsify glucose readings by replaying BLE packets, resulting in suppression of the critical alert.",stride_rule:"Zone 1 → Zone 4 (UP): Tampering applies.",component:"IoT Gateway → Device Data Svc",zone_from:"Minimal Trust",zone_to:"Standard",likelihood:"Medium",impact_rating:"Critical",explanation:"BLE without MAC allows capture-replay. A 30-minute-old reading of 80 mg/dL replayed when actual is 40 = no alert fired.",why_risk:"Critical: patient safety directly endangered. FDA 21 CFR Part 11 violation.",controls_correct:["Message Authentication Code (MAC) on every BLE packet","Timestamp + sequence number with 60-second replay window","TLS mutual auth on MQTT with per-device certificates"],controls_wrong:["BLE encryption only (encryption ≠ authentication)","Checksum verification only","Increase MQTT QoS level"],real_world:"2017 FDA recall: 465,000 St. Jude Medical pacemakers — firmware replay vulnerability. First FDA-mandated security patch for implanted cardiac devices.",owasp:"A04:2021 — Insecure Design"},
    {id:"T-402",stride:"Denial of Service",nodes:["CGM Device","IoT Gateway","Device Data Svc","Alert Service"],flows:["IoT Gateway→Device Data Svc","Device Data Svc→Alert Service"],source:"Attacker via internet (Z0)",action:"delay life-critical glucose alerts",asset:"Alert Service (Z9)",method:"flooding Device Data Service with spoofed telemetry to exhaust the Alert Service processing queue",impact:"8-minute delay on critical hypoglycaemia alert — patient suffers brain damage or death",composed:"An attacker can delay critical alerts by flooding the Device Data Service queue, resulting in fatal delay of a hypoglycaemia alert.",stride_rule:"Zone 0 can reach Alert Service via chain: DoS applies.",component:"Alert Service",zone_from:"Not in Control",zone_to:"Max Security",likelihood:"Medium",impact_rating:"Critical",explanation:"Alert Service has no priority queue. FIFO: 10,000 fake readings precede one critical alert. 8-minute delay = irreversible brain damage.",why_risk:"Critical: delayed alert = patient harm. FDA IEC 62304 Class C violation.",controls_correct:["Priority queue: critical alerts bypass ALL normal telemetry","Dead man's switch: alert on ABSENCE of expected telemetry","Separate delivery channel for critical alerts (SMS + push + direct call)"],controls_wrong:["Increase queue size","Rate limit all Device Data clients","Add second Alert Service instance (shares same FIFO queue)"],real_world:"2019 Medtronic recall: DoS via RF signal prevented insulin delivery commands. FDA Class I recall.",owasp:"A05:2021 — Security Misconfiguration"},
    {id:"T-403",stride:"Information Disclosure",nodes:["Device Data Svc","Legacy EHR"],flows:["Device Data Svc→Legacy EHR"],source:"Device Data Service (Z4)",action:"expose full patient PHI",asset:"Legacy EHR (Z0 — uncontrolled)",method:"transmitting HL7v2 messages over MLLP without TLS encryption",impact:"patient PHI captured by hospital network eavesdropping",composed:"Device Data Service exposes patient PHI by transmitting HL7v2 messages over unencrypted MLLP, resulting in PHI capture on the hospital network.",stride_rule:"Zone 4 → Zone 0 (DOWN to external uncontrolled): Information Disclosure applies.",component:"Device Data Svc → Legacy EHR",zone_from:"Standard",zone_to:"Not in Control",likelihood:"High",impact_rating:"High",explanation:"MLLP has no native encryption. Hospital networks are shared. Wireshark captures all PHI.",why_risk:"HIPAA §164.312(e)(1) violation = $50K–$1.9M per violation.",controls_correct:["TLS wrapper for MLLP (required for HIPAA)","Migrate to FHIR R4 with native TLS","Network segmentation: HL7 traffic on isolated VLAN"],controls_wrong:["Base64 encode HL7 messages","Trust hospital perimeter firewall","Encrypt only SSN field"],real_world:"2020 Universal Health Services ransomware: 400 hospitals, PHI exposed via unencrypted internal HL7 traffic.",owasp:"A02:2021 — Cryptographic Failures"},
    {id:"T-404",stride:"Spoofing",nodes:["CGM Device","IoT Gateway","Device Data Svc"],flows:["CGM Device→IoT Gateway","IoT Gateway→Device Data Svc"],source:"Attacker at patient home",action:"inject falsified glucose data as the legitimate device",asset:"IoT Gateway → Device Data Svc",method:"deploying a rogue MQTT client impersonating the patient's IoT gateway",impact:"attacker controls all glucose readings — can suppress any alert indefinitely",composed:"A physically present attacker can impersonate the IoT Gateway with a rogue MQTT client, resulting in complete control of the patient's glucose data stream.",stride_rule:"Zone 0 → IoT Gateway node: Spoofing applies — MQTT broker requires no client certificate.",component:"IoT Gateway",zone_from:"Not in Control",zone_to:"Minimal Trust",likelihood:"Medium",impact_rating:"Critical",explanation:"Without mTLS client certificates, any device connects to MQTT broker and publishes as any patient.",why_risk:"Attacker controls ALL readings indefinitely. Can suppress any alert. Targeted attack.",controls_correct:["X.509 client certificates per device (provisioned at manufacturing)","Device attestation via TPM chip + cloud attestation service","Broker-level ACL: each device only publishes to its own topic"],controls_wrong:["Username + password for MQTT","IP allowlist for patient home","Encrypt telemetry at rest only"],real_world:"2015 Hospira drug pumps: default credentials allowed impersonation of any pump — could alter dosage remotely. 35K devices affected.",owasp:"A07:2021 — Auth Failures"},
    {id:"T-405",stride:"Elevation of Privilege",nodes:["Device Data Svc","Patient DB"],flows:["Device Data Svc→Alert Service","Alert Service→Patient DB"],source:"Device Data Service (Z4)",action:"write to clinical records beyond telemetry scope",asset:"Patient DB (Z9)",method:"over-privileged IAM role granting write access to ALL Patient DB tables",impact:"telemetry processor able to alter medication dosage records and diagnosis codes",composed:"Device Data Service can alter clinical records via an over-privileged IAM role, resulting in incorrect medication records that could cause patient harm.",stride_rule:"Device Data Svc adjacent to Patient DB (Z9): EoP applies.",component:"Device Data Svc",zone_from:"Standard",zone_to:"Max Security",likelihood:"Low",impact_rating:"Critical",explanation:"Telemetry processor needs INSERT to telemetry_readings table only. IAM role grants full RW to all patient_db tables.",why_risk:"Low likelihood. Critical impact: altered medication records = wrong treatment = patient harm.",controls_correct:["Separate IAM roles per service with minimum required permissions","Patient DB split: telemetry table INSERT-only for Device Data Svc","Row-level security: service writes only rows matching its device_id"],controls_wrong:["Single admin role for operational simplicity","Read-only access to all tables","Audit log of all DB writes (detects — doesn't prevent)"],real_world:"2021 Scripps Health breach: over-privileged service account lateral movement to PACS system. 147K patients affected.",owasp:"A01:2021 — Broken Access Control"},
  ],
  attackTree:{
    title:"Attack Tree: Suppress Life-Critical Glucose Alert",
    goal:"Prevent patient from receiving a hypoglycaemia alert",
    paths:[
      {id:"pathA",label:"Path A — BLE Replay",priority:"HIGHEST",priorityCol:C.red,gateType:"AND",
       steps:[
         {id:"A1",label:"Capture BLE readings during safe glucose range",strideId:"T-401",strideType:"Tampering",difficulty:"Medium",detail:"SDR hardware ($30) captures BLE packets in minutes",component:"CGM Device"},
         {id:"A2",label:"Wait for hypoglycaemic episode",strideId:"T-401",strideType:"Tampering",difficulty:"Easy",detail:"Attacker monitors from home — timing the attack",component:"IoT Gateway"},
         {id:"A3",label:"Replay safe-range readings to gateway",strideId:"T-401",strideType:"Tampering",difficulty:"Easy",detail:"No timestamp/MAC = accepted as current reading. Alert never fires.",component:"Device Data Svc"},
       ],
       mitigations:[{step:"A1",control:"BLE MAC: captured packets have wrong MAC — replay detected immediately"},{step:"A3",control:"60-second freshness window: replayed packets from minutes ago rejected"}]
      },
      {id:"pathB",label:"Path B — Queue Flood DoS",priority:"HIGH",priorityCol:C.amber,gateType:"OR",
       steps:[
         {id:"B1",label:"Connect rogue MQTT client",strideId:"T-402",strideType:"Denial of Service",difficulty:"Easy",detail:"No client certificate required — open MQTT broker",component:"IoT Gateway"},
         {id:"B2",label:"Flood Device Data Svc with fake normal readings",strideId:"T-402",strideType:"Denial of Service",difficulty:"Easy",detail:"10,000 normal readings queue ahead of actual critical alert",component:"Device Data Svc"},
         {id:"B3",label:"Critical alert delayed 8+ minutes",strideId:"T-402",strideType:"Denial of Service",difficulty:"Easy",detail:"FIFO queue — critical alert waits behind all fake readings",component:"Alert Service"},
       ],
       mitigations:[{step:"B1",control:"X.509 client certs: rogue MQTT client cannot connect"},{step:"B3",control:"Priority queue: critical alerts preempt all normal telemetry regardless of queue depth"}]
      },
    ],
  },
  q4_validation:{
    checklist:[
      "Has replay attack protection been validated with actual BLE capture hardware?",
      "Is the alert priority queue tested under synthetic load conditions?",
      "Are all HL7 transmissions verified to use TLS in production (not just dev)?",
      "Has the Dead Man's Switch been tested — does it alert on silence as expected?",
      "Are IAM role permissions reviewed at every deployment by a security engineer?",
    ],
    gap:"Physical security of the IoT gateway at patient homes is outside our control. Risk accepted and documented — mitigated by cryptographic controls (MAC, mTLS, device attestation).",
  },
},
};


// ══ UI PRIMITIVES ══════════════════════════════════════════════════════════
const Box = ({children,style={}}) => (
  <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,padding:"16px 20px",...style}}>{children}</div>
);
const Alert = ({type="info",title,children,style={}}) => {
  const cfg={info:{bg:C.blueD,b:C.blue,ic:"◈"},warn:{bg:C.amberD,b:C.amber,ic:"⚠"},danger:{bg:C.redD,b:C.red,ic:"⚡"},success:{bg:C.greenD,b:C.green,ic:"✓"},concept:{bg:C.raised,b:C.borderHi,ic:"▸"}}[type]||{bg:C.blueD,b:C.blue,ic:"◈"};
  return <div style={{background:cfg.bg,border:`1px solid ${cfg.b}44`,borderLeft:`3px solid ${cfg.b}`,borderRadius:6,padding:"12px 16px",margin:"8px 0",...style}}>
    {title&&<div style={{fontSize:10,fontWeight:700,textTransform:"uppercase",letterSpacing:2,color:cfg.b,marginBottom:5,fontFamily:C.mono}}>{cfg.ic} {title}</div>}
    <div style={{fontSize:13.5,lineHeight:1.75,color:C.text}}>{children}</div>
  </div>;
};
const Tag = ({color,children,style={}}) => (
  <span style={{display:"inline-flex",alignItems:"center",background:`${color}20`,border:`1px solid ${color}44`,borderRadius:4,padding:"1px 8px",fontSize:11,fontWeight:700,color,fontFamily:C.mono,...style}}>{children}</span>
);
const Btn = ({children,onClick,variant="primary",disabled=false,style={}}) => {
  const v={primary:{bg:C.accent,color:"#000",b:C.accent},ghost:{bg:"transparent",color:C.sub,b:C.border},danger:{bg:C.red,color:"#fff",b:C.red},success:{bg:C.green,color:"#000",b:C.green}}[variant]||{bg:C.accent,color:"#000",b:C.accent};
  return <button onClick={onClick} disabled={disabled} style={{padding:"8px 20px",background:disabled?"#1a2332":v.bg,border:`1px solid ${disabled?C.border:v.b}`,borderRadius:5,color:disabled?C.muted:v.color,fontWeight:700,fontSize:12.5,cursor:disabled?"not-allowed":"pointer",fontFamily:C.mono,letterSpacing:.5,transition:"all .12s",...style}}>{children}</button>;
};
const Tabs = ({tabs,active,onChange}) => (
  <div style={{display:"flex",borderBottom:`1px solid ${C.border}`,marginBottom:16,overflowX:"auto",gap:0}}>
    {tabs.map((t,i)=><button key={i} onClick={()=>onChange(i)} style={{padding:"9px 18px",background:"none",border:"none",cursor:"pointer",fontSize:11,fontWeight:active===i?700:400,fontFamily:C.mono,textTransform:"uppercase",letterSpacing:.8,whiteSpace:"nowrap",color:active===i?C.accent:C.sub,borderBottom:`2px solid ${active===i?C.accent:"transparent"}`,transition:"all .12s"}}>{t}</button>)}
  </div>
);

// ══ C4 DIAGRAM — FIXED POSITION LAYOUT ═══════════════════════════════════
//
// Each workshop has a hand-authored layout blueprint: per-component (x,y),
// boundary groups, and connector routing hints.
//
// C4 conventions followed:
//   • External actors above and/or below the system
//   • Services in the centre with clear left→right or top→down reading
//   • Boundary boxes with labelled swim lanes
//   • Connectors route orthogonally (no crossing where possible)
//   • Labels on connectors: data type + protocol
//   • Node shapes: rounded rect (service), cylinder (store), person (actor)
//
// mode: "clean" | "zones" | "threats" | "mitigations"
// revealedThreats: Set<threatId> — only show badges for revealed threats
//
const C4_LAYOUTS = {
  // TechMart: Customer (external) left, third-parties right, system centre-stack
  // Boundary tab labels sit at y-11 to y+11, so nodes need y>=70 to avoid head overlap
  techmart: {
    W: 820, H: 620,
    nodes: {
      "Customer":     {x:40,  y:120, w:130, h:64, shape:"person"},
      "React SPA":    {x:300, y:80,  w:150, h:64, shape:"service"},
      "Node.js API":  {x:300, y:250, w:150, h:64, shape:"service"},
      "PostgreSQL DB":{x:300, y:450, w:150, h:68, shape:"store"},
      "Stripe":       {x:640, y:80,  w:130, h:64, shape:"external"},
      "SendGrid":     {x:640, y:200, w:130, h:64, shape:"external"},
    },
    boundaries: [
      {label:"Browser — Minimal Trust (Z1)",    x:260,y:50, w:230,h:125, zone:"Minimal Trust"},
      {label:"Application Server — Standard (Z3)",x:260,y:220,w:230,h:120, zone:"Standard"},
      {label:"Data Layer — Critical (Z7)",       x:260,y:420,w:230,h:125, zone:"Critical"},
    ],
  },
  // CloudBank: mobile external left, gateway centre-top, services row, DBs row
  cloudbank: {
    W: 860, H: 620,
    nodes: {
      "Mobile App":      {x:40,  y:120, w:140, h:64, shape:"person"},
      "API Gateway":     {x:360, y:80,  w:150, h:64, shape:"service"},
      "User Service":    {x:180, y:270, w:150, h:64, shape:"service"},
      "Payment Service": {x:520, y:270, w:160, h:64, shape:"service"},
      "User DB":         {x:150, y:460, w:150, h:68, shape:"store"},
      "Transaction DB":  {x:510, y:460, w:160, h:68, shape:"store"},
    },
    boundaries: [
      {label:"API Gateway — Minimal Trust (Z1)",  x:320,y:50, w:230,h:125, zone:"Minimal Trust"},
      {label:"Business Services — Elevated (Z5)",  x:130,y:240,w:600,h:120, zone:"Elevated"},
      {label:"Data Stores — Critical (Z7)",        x:100,y:430,w:640,h:130, zone:"Critical"},
    ],
  },
  // DataInsight: tenant external left, gateway top-centre, processing row spread, warehouse bottom-centre
  datainsight: {
    W: 860, H: 620,
    nodes: {
      "Tenant Browser":  {x:40,  y:120, w:140, h:64, shape:"person"},
      "API Gateway":     {x:360, y:80,  w:150, h:64, shape:"service"},
      "Ingestion Svc":   {x:140, y:280, w:150, h:64, shape:"service"},
      "Kafka":           {x:360, y:280, w:140, h:64, shape:"store"},
      "Query Service":   {x:570, y:280, w:150, h:64, shape:"service"},
      "Data Warehouse":  {x:360, y:460, w:150, h:68, shape:"store"},
    },
    boundaries: [
      {label:"API Gateway — Minimal Trust (Z1)",  x:320,y:50, w:230,h:125, zone:"Minimal Trust"},
      {label:"Processing Layer — Standard (Z3)",  x:100,y:250,w:660,h:130, zone:"Standard"},
      {label:"Analytics Store — Elevated (Z5)",   x:310,y:430,w:250,h:130, zone:"Elevated"},
    ],
  },
  // HealthMonitor: device external left, legacy EHR external right, IoT gateway top-centre, 
  // data service middle, alert service right-lower, patient DB bottom-centre
  healthmonitor: {
    W: 860, H: 650,
    nodes: {
      "CGM Device":      {x:40,  y:140, w:130, h:64, shape:"person"},
      "IoT Gateway":     {x:340, y:80,  w:150, h:64, shape:"service"},
      "Device Data Svc": {x:340, y:260, w:150, h:64, shape:"service"},
      "Alert Service":   {x:580, y:380, w:150, h:64, shape:"service"},
      "Patient DB":      {x:340, y:450, w:150, h:68, shape:"store"},
      "Legacy EHR":      {x:680, y:140, w:130, h:64, shape:"external"},
    },
    boundaries: [
      {label:"Edge — Minimal Trust (Z1)",         x:300,y:50, w:230,h:125, zone:"Minimal Trust"},
      {label:"Processing — Standard (Z3)",         x:300,y:230,w:230,h:120, zone:"Standard"},
      {label:"Clinical Data — Max Security (Z9)",  x:300,y:420,w:230,h:130, zone:"Max Security"},
    ],
  },
};

function C4Diagram({ws, mode="clean", selectedThreat=null, revealedThreats=null, showMitigations=false, onNodeClick=null, onFlowClick=null}) {
  const [hoverNode, setHoverNode] = useState(null);
  const [hoverFlow, setHoverFlow] = useState(null);
  const [panelThreat, setPanelThreat] = useState(null);

  const layout = C4_LAYOUTS[ws.id] || C4_LAYOUTS.techmart;
  const {W, H, nodes: nodePos, boundaries: boundaryDefs} = layout;
  const {components, flows, threats=[]} = ws;

  // Threat visibility
  const showAll = mode === "threats" || mode === "mitigations";
  const visibleIds = revealedThreats || (showAll ? new Set(threats.map(t=>t.id)) : new Set());
  const hotNodes = new Set(selectedThreat?.nodes || []);
  const hotFlows = new Set((selectedThreat?.flows || []));

  // Index: component name → data
  const compByName = Object.fromEntries(components.map(c => [c.name, c]));

  // Threat lookups
  const nodeThreats = {}, flowThreats = {};
  threats.forEach(t => {
    (t.nodes||[]).forEach(n => { nodeThreats[n]=nodeThreats[n]||[]; nodeThreats[n].push(t); });
    (t.flows||[]).forEach(f => { flowThreats[f]=flowThreats[f]||[]; flowThreats[f].push(t); });
  });

  const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

  // ── helpers for connector anchor points ──────────────────────────────
  function getAnchors(srcName, dstName) {
    const sp = nodePos[srcName], dp = nodePos[dstName];
    if (!sp || !dp) return null;
    const scx = sp.x + sp.w/2, scy = sp.y + sp.h/2;
    const dcx = dp.x + dp.w/2, dcy = dp.y + dp.h/2;
    const dx = dcx - scx, dy = dcy - scy;
    // Pick best anchor sides: prefer the face pointing toward the target
    let sx, sy, ex, ey;
    if (Math.abs(dx) >= Math.abs(dy)) {
      // horizontal dominant: exit right/left
      if (dx > 0) { sx=sp.x+sp.w; sy=scy; ex=dp.x; ey=dcy; }
      else         { sx=sp.x;      sy=scy; ex=dp.x+dp.w; ey=dcy; }
    } else {
      // vertical dominant: exit bottom/top
      if (dy > 0) { sx=scx; sy=sp.y+sp.h; ex=dcx; ey=dp.y; }
      else         { sx=scx; sy=sp.y;      ex=dcx; ey=dp.y+dp.h; }
    }
    return {sx,sy,ex,ey,scx,scy,dcx,dcy};
  }

  // ── orthogonal path builder ────────────────────────────────────────────
  function makeOrthPath(sx,sy,ex,ey, offset=0) {
    const mx = (sx+ex)/2 + offset;
    const my = (sy+ey)/2 + offset;
    if (Math.abs(sx-ex) < 4) {
      // near-vertical: straight line
      return `M${sx},${sy} L${ex},${ey}`;
    }
    if (Math.abs(sy-ey) < 4) {
      // near-horizontal
      return `M${sx},${sy} L${ex},${ey}`;
    }
    // L-bend: go halfway horizontally, then vertically
    if (Math.abs(sy-ey) > Math.abs(sx-ex)) {
      // taller than wide: bend at midY
      return `M${sx},${sy} L${sx},${my+offset} L${ex},${my+offset} L${ex},${ey}`;
    } else {
      // wider than tall: bend at midX
      return `M${sx},${sy} L${mx+offset},${sy} L${mx+offset},${ey} L${ex},${ey}`;
    }
  }

  // ── Build edges ────────────────────────────────────────────────────────
  // Track how many connectors share the same src/dst pair for offset
  const pairCount = {}, pairIdx = {};
  flows.forEach(f => {
    const k = [f.src,f.dst].sort().join("|");
    pairCount[k] = (pairCount[k]||0)+1;
  });

  const edgeEls = flows.map((f, fi) => {
    const anch = getAnchors(f.src, f.dst);
    if (!anch) return null;
    const {sx,sy,ex,ey} = anch;
    const k = [f.src,f.dst].sort().join("|");
    if (!pairIdx[k]) pairIdx[k] = 0;
    const idx = pairIdx[k]++;
    const offset = (idx - (pairCount[k]-1)/2) * 14;

    const flowKey = `${f.src}→${f.dst}`;
    const isHot = hotFlows.has(flowKey);
    const isHover = hoverFlow === flowKey;
    const fThreats = (flowThreats[flowKey]||[]).filter(t=>visibleIds.has(t.id));
    const hasThr = fThreats.length > 0;

    let col = isHot ? (showMitigations?C.green:C.red) : isHover ? C.accent : hasThr ? C.amber : "#2a3f58";
    const sw = isHot ? 2.5 : isHover ? 2 : 1.5;

    const d = makeOrthPath(sx,sy,ex,ey,offset);
    // Label midpoint
    const lx = (sx+ex)/2 + offset * .5;
    const ly = (sy+ey)/2 + offset * .5;
    const lbl = esc((f.data||"").slice(0,18));
    const proto = f.proto ? esc(f.proto) : "";
    const lblW = lbl.length * 5.8 + 16;
    const markerId = `m${fi}`;
    const clickable = onFlowClick && fThreats.length > 0;

    return (
      <g key={fi} style={{cursor:clickable?"pointer":"default"}}
        onMouseEnter={()=>setHoverFlow(flowKey)}
        onMouseLeave={()=>setHoverFlow(null)}
        onClick={()=>{ if(clickable){onFlowClick(fThreats[0]); setPanelThreat(fThreats[0]);}}}>
        <defs>
          <marker id={markerId} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <polygon points="1,1 7,4 1,7" fill={col}/>
          </marker>
        </defs>
        {isHot&&<path d={d} fill="none" stroke={col} strokeWidth={sw+5} opacity={.12}/>}
        <path d={d} fill="none" stroke={col} strokeWidth={sw}
          strokeDasharray={isHot&&showMitigations?"10,4":undefined}
          style={isHot&&!showMitigations?{animation:"flow .7s linear infinite"}:undefined}
          markerEnd={`url(#${markerId})`} opacity={isHover||isHot?1:.75}/>
        {/* Flow label pill */}
        <rect x={lx-lblW/2} y={ly-11} width={lblW} height={13} rx={4}
          fill={isHover||isHot?C.panel:C.bg} stroke={col} strokeWidth={.5} opacity={.95}/>
        <text x={lx} y={ly} textAnchor="middle" fontSize={8.5}
          fill={isHover||isHot?col:C.sub} fontFamily={C.mono} fontWeight={isHot?"700":"400"}>{lbl}</text>
        {proto&&<text x={lx} y={ly+11} textAnchor="middle" fontSize={7}
          fill={C.muted} fontFamily={C.mono}>{proto}</text>}
        {/* Threat badge on flow */}
        {hasThr && mode!=="clean" && mode!=="zones" && (
          <g>
            <circle cx={lx+lblW/2+10} cy={ly-6} r={9} fill={isHot?col:C.amber}/>
            <text x={lx+lblW/2+10} y={ly-1} textAnchor="middle" fontSize={8}
              fontWeight="900" fill="#000" fontFamily={C.mono}>{fThreats.length}</text>
          </g>
        )}
      </g>
    );
  });

  // ── Build nodes ────────────────────────────────────────────────────────
  const nodeEls = components.map(comp => {
    const p = nodePos[comp.name];
    if (!p) return null;
    const zc = C.zones[comp.zone] || C.zones["Standard"];
    const {x,y,w,h,shape} = p;
    const cx = x+w/2, cy = y+h/2;

    const isHot = hotNodes.has(comp.name);
    const isHover = hoverNode === comp.name;
    const cThreats = (nodeThreats[comp.name]||[]).filter(t=>visibleIds.has(t.id));
    const hasThr = cThreats.length > 0;

    const strokeCol = isHot?(showMitigations?C.green:C.red):isHover?C.accent:hasThr&&mode!=="clean"&&mode!=="zones"?C.amber:zc.c;
    const fillCol   = isHot?(showMitigations?`${C.green}14`:`${C.red}14`):isHover?`${C.accent}0d`:C.card;
    const sw        = isHot||isHover ? 2 : 1.5;
    const glowF     = isHot?`drop-shadow(0 0 10px ${strokeCol}99)`:isHover?`drop-shadow(0 0 7px ${C.accent}66)`:`drop-shadow(0 0 2px ${zc.c}22)`;

    // Connector click
    const handleClick = () => {
      if (onNodeClick) {
        onNodeClick(comp, cThreats);
        if (cThreats.length) setPanelThreat(cThreats[0]);
      }
    };

    // Type label
    const typeLabel = shape==="person"?"Actor":shape==="external"?"External":shape==="store"?"Data Store":"Service";
    const typeIcon  = shape==="person"?"◇":shape==="external"?"◇":shape==="store"?"⊟":"▢";

    return (
      <g key={comp.name} style={{cursor:onNodeClick?"pointer":"default",filter:glowF}}
        onMouseEnter={()=>setHoverNode(comp.name)}
        onMouseLeave={()=>setHoverNode(null)}
        onClick={handleClick}>

        {/* Person shape: rounded rect with head bump */}
        {(shape==="person"||shape==="external") && <>
          <ellipse cx={cx} cy={y-8} rx={12} ry={12} fill={fillCol} stroke={strokeCol} strokeWidth={sw}/>
          <rect x={x} y={y+6} width={w} height={h-6} rx={8} fill={fillCol} stroke={strokeCol} strokeWidth={sw}/>
        </>}

        {/* Service: rounded rect with double top line (C4 style) */}
        {shape==="service" && <>
          <rect x={x} y={y} width={w} height={h} rx={8} fill={fillCol} stroke={strokeCol} strokeWidth={sw}/>
          {/* C4 top accent bar */}
          <rect x={x} y={y} width={w} height={14} rx={8} fill={`${strokeCol}22`} stroke="none"/>
          <rect x={x+8} y={y+5} width={w-16} height={3} rx={1.5} fill={strokeCol} opacity={.6}/>
        </>}

        {/* Data Store: proper cylinder */}
        {shape==="store" && <>
          {/* Body */}
          <rect x={x} y={y+10} width={w} height={h-20} fill={fillCol} stroke={strokeCol} strokeWidth={sw}/>
          {/* Top ellipse */}
          <ellipse cx={cx} cy={y+10} rx={w/2} ry={10} fill={fillCol} stroke={strokeCol} strokeWidth={sw}/>
          {/* Bottom ellipse */}
          <ellipse cx={cx} cy={y+h-10} rx={w/2} ry={10} fill={fillCol} stroke={strokeCol} strokeWidth={sw}/>
          {/* Inner curve on top */}
          <path d={`M${x},${y+10} Q${cx},${y+22} ${x+w},${y+10}`} fill="none" stroke={strokeCol} strokeWidth={.7} opacity={.4}/>
        </>}

        {/* Type tag — bottom-left corner */}
        <rect x={x+4} y={y+h-16} width={typeLabel.length*5.8+10} height={13} rx={6}
          fill={zc.c} opacity={.9}/>
        <text x={x+9} y={y+h-5} fontSize={7.5} fontWeight="700" fill="#000" fontFamily={C.mono}>{typeLabel}</text>

        {/* Zone badge — top-right */}
        <rect x={x+w-28} y={y+2} width={25} height={13} rx={6} fill={zc.c} opacity={.85}/>
        <text x={x+w-15} y={y+12} textAnchor="middle" fontSize={8} fontWeight="700" fill="#000" fontFamily={C.mono}>{zc.badge}</text>

        {/* Component name — centred, bold */}
        <text x={cx} y={cy-4} textAnchor="middle" fontSize={12} fontWeight="700"
          fill={isHot?strokeCol:isHover?C.accent:C.text} fontFamily={C.mono}>{esc(comp.name)}</text>

        {/* Description — small, muted */}
        <text x={cx} y={cy+11} textAnchor="middle" fontSize={8.5}
          fill={C.sub} fontFamily={C.body}>{esc((comp.desc||"").slice(0,28))}</text>

        {/* Threat badge — top-left (only in threat modes) */}
        {hasThr && mode!=="clean" && mode!=="zones" && (
          <g>
            <circle cx={x+14} cy={y+2} r={11} fill={isHot?(showMitigations?C.green:C.red):C.amber}/>
            <text x={x+14} y={y+7} textAnchor="middle" fontSize={9} fontWeight="900" fill="#000" fontFamily={C.mono}>{cThreats.length}</text>
          </g>
        )}
        {showMitigations&&isHot&&(
          <g>
            <circle cx={x+14} cy={y+2} r={11} fill={C.green}/>
            <text x={x+14} y={y+7} textAnchor="middle" fontSize={11} fill="#000">✓</text>
          </g>
        )}
      </g>
    );
  });

  // ── Boundary swim-lane boxes ─────────────────────────────────────────
  const boundaryEls = boundaryDefs.map((b,i) => {
    const zc = C.zones[b.zone] || C.zones["Standard"];
    return (
      <g key={b.label}>
        {/* Swim lane box */}
        <rect x={b.x} y={b.y} width={b.w} height={b.h} rx={10}
          fill={zc.bg} stroke={zc.c} strokeWidth={1.5} strokeDasharray="6,3" opacity={.6}/>
        {/* Label tab */}
        <rect x={b.x+12} y={b.y-11} width={b.label.length*6.2+16} height={22} rx={5}
          fill={C.panel} stroke={zc.c} strokeWidth={1.5}/>
        <text x={b.x+20} y={b.y+5} fontSize={9} fontWeight="700" fill={zc.c}
          fontFamily={C.mono} letterSpacing={.8}>{esc(b.label)}</text>
        {/* Trust boundary line between zones */}
        {i > 0 && (
          <g opacity={.5}>
            <line x1={b.x-2} y1={b.y-1} x2={b.x+b.w+2} y2={b.y-1}
              stroke={C.purple} strokeWidth={1} strokeDasharray="4,3"/>
            <rect x={b.x+b.w/2-52} y={b.y-10} width={104} height={18} rx={4}
              fill={C.panel} stroke={`${C.purple}55`} strokeWidth={1}/>
            <text x={b.x+b.w/2} y={b.y+3} textAnchor="middle" fontSize={8}
              fill={C.purple} fontFamily={C.mono} fontWeight="700">TRUST BOUNDARY</text>
          </g>
        )}
      </g>
    );
  });

  // ── Legend ─────────────────────────────────────────────────────────────
  const legendItems = [
    {shape:"rect",col:C.accent,lbl:"Service"},
    {shape:"cyl",col:C.amber,lbl:"Data Store"},
    {shape:"person",col:C.sub,lbl:"External Actor"},
    ...(mode!=="clean"&&mode!=="zones"?[
      {shape:"circle",col:C.amber,lbl:"Threats"},
      ...(showMitigations?[{shape:"circle",col:C.green,lbl:"Mitigated"}]:
                          [{shape:"circle",col:C.red,lbl:"Selected"}]),
    ]:[]),
    {shape:"dashes",col:C.purple,lbl:"Trust Boundary"},
  ];

  const inline = panelThreat && (mode==="threats"||mode==="mitigations");

  return (
    <div style={{borderRadius:10,border:`1px solid ${C.border}`,background:C.panel,overflow:"hidden"}}>
      {/* Header */}
      <div style={{padding:"10px 18px",background:C.raised,borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div style={{display:"flex",gap:12,alignItems:"center"}}>
          <span style={{fontFamily:C.display,fontSize:15,color:C.accent,letterSpacing:2}}>{esc(ws.name)}</span>
          <Tag color={mode==="clean"||mode==="zones"?C.muted:showMitigations?C.green:C.amber} style={{fontSize:9}}>
            {mode==="clean"?"ARCHITECTURE VIEW":mode==="zones"?"ZONE VIEW":showMitigations?"MITIGATION MAP":"THREAT MAP"}
          </Tag>
        </div>
        {(mode==="threats"||mode==="mitigations")&&
          <span style={{fontSize:9.5,color:C.muted,fontFamily:C.mono}}>Click nodes &amp; flows to inspect</span>}
      </div>

      {/* SVG canvas */}
      <div style={{overflowX:"auto"}}>
        <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} style={{display:"block",minWidth:Math.min(W,400)}}>
          <defs>
            <style>{`@keyframes flow{0%{stroke-dashoffset:20}100%{stroke-dashoffset:0}}`}</style>
            {/* Subtle dot grid */}
            <pattern id={`dotgrid-${ws.id}`} width="28" height="28" patternUnits="userSpaceOnUse">
              <circle cx="14" cy="14" r="1" fill={C.border} opacity=".35"/>
            </pattern>
          </defs>
          <rect width={W} height={H} fill={`url(#dotgrid-${ws.id})`}/>

          {/* Draw boundaries behind everything */}
          {boundaryEls}
          {/* Edges behind nodes */}
          {edgeEls}
          {/* Nodes on top */}
          {nodeEls}

          {/* Legend strip at bottom */}
          <g transform={`translate(12,${H-22})`}>
            {legendItems.map(({shape,col,lbl},i)=>(
              <g key={lbl} transform={`translate(${i*116},0)`}>
                {shape==="rect"&&<rect x={0} y={-7} width={12} height={12} rx={2} fill={col} opacity={.8}/>}
                {shape==="cyl"&&<ellipse cx={6} cy={-1} rx={6} ry={4} fill={col} opacity={.8}/>}
                {shape==="person"&&<ellipse cx={6} cy={-1} rx={5} ry={5} fill={col} opacity={.6}/>}
                {shape==="circle"&&<circle cx={6} cy={-1} r={6} fill={col} opacity={.85}/>}
                {shape==="dashes"&&<line x1={0} y1={-1} x2={12} y2={-1} stroke={col} strokeWidth={2} strokeDasharray="3,2"/>}
                <text x={16} y={5} fontSize={9} fill={C.muted} fontFamily={C.mono}>{lbl}</text>
              </g>
            ))}
          </g>
        </svg>
      </div>

      {/* Inline threat detail panel (appears below diagram) */}
      {inline && panelThreat && (
        <div style={{borderTop:`1px solid ${C.border}`,background:C.card,padding:"14px 18px"}}>
          <ThreatDetailPanel threat={panelThreat} showMitigations={showMitigations}
            onClose={()=>setPanelThreat(null)}/>
        </div>
      )}
    </div>
  );
}

// ── Threat detail panel ──────────────────────────────────────────────────
function ThreatDetailPanel({threat, showMitigations=false, onClose}) {
  const [expanded, setExpanded] = useState(false);
  if (!threat) return null;
  const sc = C[threat.stride?.[0]] || C.accent;
  return (
    <div style={{border:`1px solid ${sc}44`,borderLeft:`3px solid ${sc}`,borderRadius:8,
      background:C.card,padding:"14px 18px"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
        <div style={{display:"flex",gap:7,flexWrap:"wrap"}}>
          <Tag color={sc}>{threat.stride}</Tag>
          <Tag color={C.amber}>{threat.id}</Tag>
          <Tag color={threat.impact_rating==="Critical"?C.red:C.amber}>{threat.likelihood} · {threat.impact_rating}</Tag>
        </div>
        <button onClick={onClose} style={{background:"none",border:`1px solid ${C.border}`,
          borderRadius:4,color:C.muted,padding:"1px 8px",fontSize:11,fontFamily:C.mono,cursor:"pointer"}}>✕</button>
      </div>
      <div style={{fontFamily:C.mono,fontSize:12.5,color:C.text,lineHeight:1.8,
        padding:"8px 12px",background:C.panel,borderRadius:5,marginBottom:8}}>{threat.composed}</div>
      {expanded ? (
        <div>
          <p style={{fontSize:13,color:C.sub,lineHeight:1.75,marginBottom:10}}>{threat.explanation}</p>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
            <div style={{background:C.greenD,border:`1px solid ${C.green}22`,borderRadius:6,padding:"10px 12px"}}>
              <div style={{fontSize:9,fontWeight:700,color:C.green,textTransform:"uppercase",
                letterSpacing:2,marginBottom:5,fontFamily:C.mono}}>✓ Correct Controls</div>
              {(threat.controls_correct||[]).map((c,i)=>(
                <div key={i} style={{display:"flex",gap:6,fontSize:12.5,color:C.text,
                  padding:"3px 0",lineHeight:1.5}}><span style={{color:C.green,flexShrink:0}}>✓</span>{c}</div>
              ))}
            </div>
            <div style={{background:C.redD,border:`1px solid ${C.red}22`,borderRadius:6,padding:"10px 12px"}}>
              <div style={{fontSize:9,fontWeight:700,color:C.red,textTransform:"uppercase",
                letterSpacing:2,marginBottom:5,fontFamily:C.mono}}>✗ Ineffective</div>
              {(threat.controls_wrong||[]).map((c,i)=>(
                <div key={i} style={{display:"flex",gap:6,fontSize:12.5,color:C.sub,
                  padding:"3px 0",lineHeight:1.5}}><span style={{color:C.red,flexShrink:0}}>✗</span>{c}</div>
              ))}
            </div>
          </div>
          <div style={{fontSize:12,color:C.muted,fontFamily:C.mono,background:C.raised,
            borderRadius:5,padding:"8px 12px",marginBottom:8}}>📋 {threat.real_world}</div>
          <Tag color={C.accent}>{threat.owasp}</Tag>
          <button onClick={()=>setExpanded(false)} style={{display:"block",marginTop:8,
            background:"none",border:`1px solid ${C.border}`,borderRadius:4,color:C.sub,
            padding:"3px 12px",fontSize:10,fontFamily:C.mono,cursor:"pointer"}}>▲ Collapse</button>
        </div>
      ) : (
        <button onClick={()=>setExpanded(true)} style={{background:"none",border:`1px solid ${C.border}`,
          borderRadius:4,color:C.sub,padding:"5px 14px",fontSize:11,fontFamily:C.mono,cursor:"pointer"}}>
          ▼ Show detail + controls
        </button>
      )}
    </div>
  );
}

// ══ STEP BAR ══════════════════════════════════════════════════════════════
const STEPS = [
  {id:"why",      label:"Why TM?",        icon:"①",  phase:"Foundation"},
  {id:"s101",     label:"STRIDE 101",     icon:"②",  phase:"Foundation"},
  {id:"q1",       label:"The System",     icon:"Q1", phase:"Understand"},
  {id:"q2arch",   label:"Architecture",   icon:"Q2", phase:"Understand"},
  {id:"q2zones",  label:"Zone Labels",    icon:"③",  phase:"Discover"},
  {id:"q2stride", label:"Find Threats",   icon:"④",  phase:"Discover"},
  {id:"q2tree",   label:"Attack Paths",   icon:"⑤",  phase:"Discover"},
  {id:"q3",       label:"Mitigations",    icon:"Q3", phase:"Respond"},
  {id:"q4",       label:"Validate",       icon:"Q4", phase:"Respond"},
  {id:"cert",     label:"Certificate",    icon:"★",  phase:"Complete"},
];

const PHASE_COLORS = {Foundation:C.blue,Understand:C.accent,Discover:C.amber,Respond:C.green,Complete:C.purple};

function StepBar({current}) {
  const ci = STEPS.findIndex(s=>s.id===current);
  const phases = [...new Set(STEPS.map(s=>s.phase))];
  return (
    <div>
      <div style={{display:"flex",gap:3,marginBottom:8,overflowX:"auto"}}>
        {phases.map(ph=>{
          const phSteps = STEPS.filter(s=>s.phase===ph);
          const start = STEPS.indexOf(phSteps[0]);
          const end = STEPS.indexOf(phSteps[phSteps.length-1]);
          const isActive = ci>=start&&ci<=end, isDone=ci>end;
          const col = PHASE_COLORS[ph]||C.accent;
          return <div key={ph} style={{flex:phSteps.length,padding:"4px 8px",borderRadius:5,
            background:isDone?`${col}18`:isActive?`${col}12`:C.raised,
            border:`1px solid ${isDone?col:isActive?`${col}66`:C.border}`,textAlign:"center"}}>
            <span style={{fontSize:8,fontWeight:700,fontFamily:C.mono,textTransform:"uppercase",
              letterSpacing:1,color:isDone?col:isActive?col:C.muted}}>{ph}</span>
          </div>;
        })}
      </div>
      <div style={{display:"flex",alignItems:"center",overflowX:"auto"}}>
        {STEPS.map((s,i)=>{
          const done=i<ci,active=i===ci;
          return <div key={s.id} style={{display:"flex",alignItems:"center"}}>
            <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:2,minWidth:56}}>
              <div style={{width:26,height:26,borderRadius:4,display:"flex",alignItems:"center",
                justifyContent:"center",fontSize:active?11:10,fontWeight:700,fontFamily:C.mono,
                background:done?C.greenD:active?C.blueD:C.raised,
                border:`1.5px solid ${done?C.green:active?C.accent:C.border}`,
                color:done?C.green:active?C.accent:C.muted,
                boxShadow:active?`0 0 10px ${C.accent}44`:"none",transition:"all .2s"}}>
                {done?"✓":s.icon}
              </div>
              <span style={{fontSize:7,fontWeight:active?700:400,fontFamily:C.mono,textAlign:"center",
                color:done?C.green:active?C.text:C.muted,textTransform:"uppercase",
                letterSpacing:.3,whiteSpace:"nowrap"}}>{s.label}</span>
            </div>
            {i<STEPS.length-1&&<div style={{width:8,height:1.5,
              background:done?C.green:C.border,marginBottom:14,flexShrink:0}}/>}
          </div>;
        })}
      </div>
    </div>
  );
}

// ── QUIZ MINI ─────────────────────────────────────────────────────────────
function QuizMini({q,onPass}) {
  const [sel,setSel]=useState(null);
  const [sub,setSub]=useState(false);
  const ok=sub&&sel===q.correct;
  useEffect(()=>{if(ok&&onPass)onPass();},[ok]);
  return (
    <Box style={{borderTop:`2px solid ${C.blue}`,marginTop:12}}>
      <div style={{fontSize:10,fontWeight:700,color:C.blue,textTransform:"uppercase",
        letterSpacing:2,marginBottom:8,fontFamily:C.mono}}>◈ Knowledge Check</div>
      <p style={{fontSize:13.5,fontWeight:600,color:C.text,marginBottom:12,lineHeight:1.6}}>{q.q}</p>
      {q.opts.map((o,i)=>{
        let bg=C.raised,brd=C.border,col=C.sub;
        if(sub){if(i===q.correct){bg=C.greenD;brd=C.green;col=C.green;}
          else if(i===sel){bg=C.redD;brd=C.red;col=C.red;}}
        else if(sel===i){bg=C.blueD;brd=C.blue;col=C.blue;}
        return <div key={i} onClick={()=>!sub&&setSel(i)}
          style={{background:bg,border:`1px solid ${brd}`,borderRadius:5,padding:"9px 14px",
            margin:"5px 0",cursor:sub?"default":"pointer",color:col,fontSize:13,
            lineHeight:1.5,transition:"all .12s",userSelect:"none"}}>
          <span style={{fontFamily:C.mono,marginRight:10,fontSize:10,opacity:.5}}>{String.fromCharCode(65+i)}.</span>{o}
        </div>;
      })}
      {!sub&&<Btn onClick={()=>{if(sel!==null)setSub(true);}} disabled={sel===null}
        style={{marginTop:10,fontSize:11}}>SUBMIT</Btn>}
      {sub&&<div style={{marginTop:10,padding:"10px 14px",background:ok?C.greenD:C.redD,
        border:`1px solid ${ok?C.green:C.red}44`,borderRadius:5}}>
        <div style={{fontWeight:700,color:ok?C.green:C.red,fontFamily:C.mono,marginBottom:4}}>
          {ok?"✓ CORRECT":"✗ INCORRECT"}</div>
        <p style={{fontSize:13,color:C.text,lineHeight:1.7,margin:0}}>{q.why}</p>
        {!ok&&<Btn variant="ghost" onClick={()=>{setSel(null);setSub(false);}}
          style={{marginTop:8,fontSize:10,padding:"4px 12px"}}>RETRY</Btn>}
      </div>}
    </Box>
  );
}

// ══ STEP 00: WHY THREAT MODELING ══════════════════════════════════════════
function StepWhy({onNext}) {
  const [tab,setTab]=useState(0);
  return (
    <div className="fu">
      <div style={{marginBottom:20}}>
        <div style={{fontFamily:C.display,fontSize:38,color:C.accent,letterSpacing:2,lineHeight:1,marginBottom:8}}>WHAT IS THREAT MODELING?</div>
        <p style={{fontSize:15,color:C.sub,maxWidth:640,lineHeight:1.85}}>A <strong style={{color:C.text}}>structured, repeatable process</strong> for identifying security problems before attackers do — and deciding what to do about each one.</p>
      </div>
      <Alert type="concept">IBM Systems Sciences: fixing a security defect at <strong style={{color:C.accent}}>design time</strong> costs $80–$960. In production: $7,600–$15,000. After release: up to $93,000. Threat modeling is <strong style={{color:C.accent}}>security economics</strong>.</Alert>
      <Tabs tabs={["Business Case","4-Question Framework","Methods Compared","Where STRIDE Fits"]} active={tab} onChange={setTab}/>
      {tab===0&&<div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(240px,1fr))",gap:12}}>
        {[{e:"💸",h:"Cost of Bugs",b:"Defects at design time cost 10–100× less to fix than in production. Threat modeling is the cheapest security investment available."},
          {e:"⏱",h:"Security Debt",b:"Every feature shipped without a threat model adds implicit liability — financial, regulatory, reputational."},
          {e:"🏛",h:"Regulatory",b:"GDPR Art.25 requires security by design. PCI-DSS Req.6 requires threat analysis. HIPAA requires risk assessment."},
          {e:"🔁",h:"Living Process",b:"Not a one-time document. Every architectural change should trigger a threat model update."},
          {e:"🤝",h:"Shared Language",b:"Creates common vocabulary for engineers, security, and stakeholders. STRIDE gives everyone the same six categories."},
          {e:"🎯",h:"Focused Effort",b:"Without a model, security is scattered. With one, every engineer knows which components need hardening most."},
        ].map(p=><Box key={p.h} style={{borderTop:`2px solid ${C.accent}`}}>
          <div style={{fontSize:22,marginBottom:8}}>{p.e}</div>
          <div style={{fontWeight:700,color:C.text,fontSize:13,marginBottom:6,fontFamily:C.mono}}>{p.h}</div>
          <p style={{fontSize:13,color:C.sub,lineHeight:1.75,margin:0}}>{p.b}</p>
        </Box>)}
      </div>}
      {tab===1&&<div>
        <Alert type="info" title="Shostack's 4-Question Framework — this lab follows all four in order"/>
        {[{q:"Q1",col:C.accent,l:"What are we working on?",b:"Understand the system, assets, trust boundaries, and assumptions. Everyone must agree on what's in scope before finding threats.",lab:"System → Assets → Assumptions → Architecture Rationale"},
          {q:"Q2",col:C.blue,l:"What can go wrong?",b:"Discover threats using STRIDE. You will work from a clean diagram — no hints. Each step earns you the right to see more.",lab:"Zone Labelling → Threat Discovery → Attack Path Simulation"},
          {q:"Q3",col:C.amber,l:"What are we going to do about it?",b:"Mitigate, Eliminate, Transfer, or Accept each threat. Document the decision — not just the control.",lab:"Control Selection → Full Threat+Mitigation Map"},
          {q:"Q4",col:C.green,l:"Did we do a good enough job?",b:"Validate coverage, quality, and gaps. Are mitigations implemented — not just planned?",lab:"Coverage Check → Gap Documentation → Score"},
        ].map(item=><Box key={item.q} style={{marginBottom:10,borderLeft:`3px solid ${item.col}`}}>
          <div style={{display:"flex",gap:12,alignItems:"center",marginBottom:8}}>
            <div style={{width:36,height:36,borderRadius:4,background:`${item.col}20`,border:`1.5px solid ${item.col}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:900,color:item.col,fontFamily:C.display,letterSpacing:1}}>{item.q}</div>
            <div style={{fontWeight:700,color:C.text,fontSize:15}}>{item.l}</div>
          </div>
          <p style={{fontSize:13.5,color:C.sub,lineHeight:1.75,marginBottom:6}}>{item.b}</p>
          <div style={{background:C.panel,borderRadius:5,padding:"6px 12px",fontSize:11,color:C.muted,fontFamily:C.mono}}><span style={{color:item.col}}>Lab: </span>{item.lab}</div>
        </Box>)}
      </div>}
      {tab===2&&<div style={{overflowX:"auto"}}>
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:13,fontFamily:C.mono}}>
          <thead><tr style={{background:C.raised}}>{["Method","Best For","Strength","Gap"].map(h=><th key={h} style={{padding:"10px 12px",textAlign:"left",color:C.sub,fontSize:10,textTransform:"uppercase",letterSpacing:1.5}}>{h}</th>)}</tr></thead>
          <tbody>{[
            ["STRIDE","Per-component threats from DFDs","Systematic, exhaustive, teachable","Misses business logic + supply chain"],
            ["PASTA","Risk-based, attacker-centric","Business context integration","Complex and time-intensive"],
            ["LINDDUN","Privacy threat modeling","GDPR/privacy focused","Narrowly scoped to privacy"],
            ["Attack Trees","Specific attacker goal paths","Shows exploitation chains","Needs STRIDE first"],
          ].map(([m,f,s,g],i)=><tr key={m} style={{background:i%2===0?C.card:C.panel,borderBottom:`1px solid ${C.border}`}}>
            <td style={{padding:"8px 12px",color:m==="STRIDE"?C.accent:C.text,fontWeight:m==="STRIDE"?700:400}}>{m}</td>
            <td style={{padding:"8px 12px",color:C.sub,fontSize:12}}>{f}</td>
            <td style={{padding:"8px 12px",color:C.green,fontSize:12}}>{s}</td>
            <td style={{padding:"8px 12px",color:C.amber,fontSize:12}}>{g}</td>
          </tr>)}</tbody>
        </table>
      </div>}
      {tab===3&&<div>
        <Alert type="warn" title="STRIDE is a tool — not a complete framework">A mnemonic for checking 6 threat categories per DFD element. Systematic. Teachable. NOT a complete security framework alone.</Alert>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
          <Box><div style={{fontWeight:700,color:C.green,marginBottom:8,fontFamily:C.mono,fontSize:12}}>STRIDE IS GOOD AT</div>
            {["Systematic — won't skip common categories","Works per DFD element","Teachable across teams","Works at design time — no running system needed"].map((s,i)=><div key={i} style={{display:"flex",gap:8,padding:"4px 0",fontSize:13,color:C.sub}}><span style={{color:C.green}}>✓</span>{s}</div>)}</Box>
          <Box><div style={{fontWeight:700,color:C.amber,marginBottom:8,fontFamily:C.mono,fontSize:12}}>STRIDE MISSES</div>
            {["Business logic threats","Supply chain threats","AI/LLM threats (prompt injection)","Physical security","Social engineering"].map((s,i)=><div key={i} style={{display:"flex",gap:8,padding:"4px 0",fontSize:13,color:C.sub}}><span style={{color:C.amber}}>△</span>{s}</div>)}</Box>
        </div>
      </div>}
      <div style={{display:"flex",justifyContent:"flex-end",marginTop:20}}>
        <Btn onClick={onNext}>NEXT: STRIDE 101 ▶</Btn>
      </div>
    </div>
  );
}

// ══ STEP 01: STRIDE 101 ═══════════════════════════════════════════════════
function StepS101({onNext,onBack}) {
  const [sel,setSel]=useState(null);
  const [passed,setPassed]=useState(new Set());
  const rule=sel!==null?STRIDE_GUIDE[sel]:null;
  const canProceed=passed.size>=3;
  return (
    <div className="fu">
      <div style={{fontFamily:C.display,fontSize:28,color:C.accent,letterSpacing:2,marginBottom:6}}>STRIDE 101</div>
      <Alert type="concept">Six categories. Every DFD element gets checked against each one. <strong style={{color:C.text}}>Pass 3+ knowledge checks to unlock the workshop.</strong></Alert>
      <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
        {STRIDE_GUIDE.map((r,i)=><button key={r.letter} onClick={()=>setSel(i)}
          style={{padding:"8px 14px",background:sel===i?`${r.color}18`:C.panel,
            border:`1.5px solid ${sel===i?r.color:passed.has(i)?`${r.color}55`:C.border}`,
            borderRadius:5,cursor:"pointer",display:"flex",gap:8,alignItems:"center",transition:"all .12s"}}>
          <span style={{fontSize:16,fontWeight:900,color:r.color,fontFamily:C.display}}>{r.letter}</span>
          <span style={{fontSize:11,color:sel===i?r.color:C.sub,fontFamily:C.mono}}>{r.name}</span>
          {passed.has(i)&&<span style={{color:C.green,fontSize:10}}>✓</span>}
        </button>)}
      </div>
      {sel===null&&(
        <Box style={{textAlign:"center",padding:"40px 20px",borderTop:`2px solid ${C.border}`}}>
          <div style={{fontSize:32,marginBottom:10}}>☝</div>
          <div style={{color:C.sub,fontSize:14}}>Select a letter above to study that STRIDE category and take its knowledge check.</div>
        </Box>
      )}
      {sel!==null&&rule&&(
      <Box key={sel} style={{borderTop:`3px solid ${rule.color}`}}>
        <div style={{display:"flex",gap:12,alignItems:"center",marginBottom:14}}>
          <div style={{width:52,height:52,borderRadius:5,background:`${rule.color}18`,
            border:`2px solid ${rule.color}`,display:"flex",alignItems:"center",justifyContent:"center",
            fontSize:26,fontWeight:900,color:rule.color,fontFamily:C.display}}>{rule.letter}</div>
          <div>
            <div style={{fontFamily:C.display,fontSize:22,color:rule.color,letterSpacing:1}}>{rule.name.toUpperCase()}</div>
            <div style={{fontSize:14,color:C.text,fontStyle:"italic",marginTop:2}}>{rule.oneLiner}</div>
          </div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
          <div>
            <div style={{fontSize:9,fontWeight:700,textTransform:"uppercase",letterSpacing:2,color:C.muted,marginBottom:5,fontFamily:C.mono}}>What the attacker does</div>
            <p style={{fontSize:13,color:C.text,lineHeight:1.75,margin:0}}>{rule.technical}</p>
          </div>
          <div style={{background:`${rule.color}10`,border:`1px solid ${rule.color}22`,borderRadius:6,padding:"12px 14px"}}>
            <div style={{fontSize:9,fontWeight:700,textTransform:"uppercase",letterSpacing:2,color:rule.color,marginBottom:5,fontFamily:C.mono}}>Real example</div>
            <p style={{fontSize:12.5,color:C.text,lineHeight:1.7,margin:0}}>{rule.realExample}</p>
          </div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
          <div style={{background:C.raised,borderRadius:5,padding:"10px 12px"}}>
            <div style={{fontSize:9,fontWeight:700,textTransform:"uppercase",letterSpacing:1.5,color:C.muted,marginBottom:5,fontFamily:C.mono}}>DFD rule</div>
            <p style={{fontSize:12.5,color:C.sub,margin:0,lineHeight:1.6}}>{rule.dfdRule}</p>
          </div>
          <div style={{background:C.raised,borderRadius:5,padding:"10px 12px"}}>
            <div style={{fontSize:9,fontWeight:700,textTransform:"uppercase",letterSpacing:1.5,color:C.muted,marginBottom:5,fontFamily:C.mono}}>Defence</div>
            <p style={{fontSize:12.5,color:C.sub,margin:0,lineHeight:1.6}}>{rule.defence}</p>
          </div>
        </div>
        {/* key=sel forces full remount when switching letters — prevents stale quiz state */}
        <QuizMini key={sel} q={rule.quiz} onPass={(idx=>()=>setPassed(p=>new Set([...p,idx])))(sel)}/>
      </Box>
      )}
      {canProceed&&<Alert type="success" style={{marginTop:12}}
        title={`${passed.size}/6 checks passed — Workshop unlocked`}>
        You understand the STRIDE categories. Now apply them to a real system.</Alert>}
      <div style={{display:"flex",justifyContent:"space-between",marginTop:20}}>
        <Btn variant="ghost" onClick={onBack}>◀ BACK</Btn>
        <Btn onClick={onNext} disabled={!canProceed}>{canProceed?"NEXT: THE SYSTEM ▶":"Pass 3+ checks to continue"}</Btn>
      </div>
    </div>
  );
}

// ══ STEP Q1: System — Assets — Assumptions — Why This Architecture ════════
function StepQ1({ws,onNext,onBack}) {
  const [tab,setTab]=useState(0);
  const [seen,setSeen]=useState(new Set([0]));
  function goTab(i){setTab(i);setSeen(s=>new Set([...s,i]));}
  const canProceed=seen.size>=4;
  const ar=ws.archRationale;
  return (
    <div className="fu">
      <div style={{display:"flex",gap:12,marginBottom:16,alignItems:"center"}}>
        <div style={{width:44,height:44,borderRadius:5,background:`${C.accent}18`,
          border:`1.5px solid ${C.accent}`,display:"flex",alignItems:"center",justifyContent:"center",
          fontFamily:C.display,fontSize:18,color:C.accent}}>Q1</div>
        <div>
          <div style={{fontFamily:C.display,fontSize:24,color:C.text,letterSpacing:1}}>WHAT ARE WE WORKING ON?</div>
          <div style={{fontSize:12,color:C.muted,fontFamily:C.mono}}>Read all 4 tabs ({seen.size}/4)</div>
        </div>
      </div>
      <Tabs tabs={["System","Assets","Assumptions","Why This Architecture?"]} active={tab} onChange={goTab}/>
      {tab===0&&<div>
        <Box>
          <div style={{fontSize:10,fontWeight:700,textTransform:"uppercase",letterSpacing:2,color:C.muted,marginBottom:8,fontFamily:C.mono}}>System Description</div>
          <p style={{fontSize:14,color:C.text,lineHeight:1.85,marginBottom:12}}>{ws.description}</p>
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            {ws.compliance.map(c=><Tag key={c} color={C.amber}>{c}</Tag>)}
            <Tag color={C.blue}>{ws.businessContext}</Tag>
          </div>
        </Box>
      </div>}
      {tab===1&&<div>
        <Alert type="warn" title="Assets first — before threats. Every threat is ultimately an attack on an asset."/>
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
          <thead><tr style={{background:C.raised}}>{["Asset","Classification","Business Impact"].map(h=><th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.sub,fontSize:10,textTransform:"uppercase",letterSpacing:1.5,fontFamily:C.mono}}>{h}</th>)}</tr></thead>
          <tbody>{ws.assets.map((a,i)=>{
            const col=a.classification==="PCI-Regulated"?C.red:a.classification==="PHI"||a.classification==="Safety-Critical"?C.purple:a.classification==="Confidential"?C.amber:a.classification==="Sensitive"?C.blue:C.sub;
            return <tr key={a.name} style={{background:i%2===0?C.card:C.panel,borderBottom:`1px solid ${C.border}`}}>
              <td style={{padding:"10px 14px",color:C.text,fontWeight:600}}>{a.name}</td>
              <td style={{padding:"10px 14px"}}><Tag color={col}>{a.classification}</Tag></td>
              <td style={{padding:"10px 14px",color:C.sub,fontSize:12.5}}>{a.impact}</td>
            </tr>;
          })}</tbody>
        </table>
      </div>}
      {tab===2&&<div>
        <Alert type="warn" title="Undocumented assumptions are hidden vulnerabilities."/>
        {ws.assumptions.map((a,i)=><div key={i} style={{display:"flex",gap:12,padding:"10px 14px",
          background:i%2===0?C.card:C.panel,border:`1px solid ${C.border}`,borderLeft:`3px solid ${C.amber}`,
          borderRadius:6,marginBottom:6}}>
          <span style={{color:C.amber,fontFamily:C.mono,fontSize:11,flexShrink:0,paddingTop:2}}>A{i+1}</span>
          <span style={{fontSize:13.5,color:C.text,lineHeight:1.7}}>{a}</span>
        </div>)}
      </div>}
      {tab===3&&ar&&<div>
        <Alert type="concept" title="Why this architecture came about">{ar.summary}</Alert>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:14}}>
          {ar.decisions.map(d=><Box key={d.title} style={{borderTop:`2px solid ${C.blue}`}}>
            <div style={{display:"flex",gap:10,marginBottom:8,alignItems:"center"}}>
              <span style={{fontSize:20}}>{d.icon}</span>
              <div style={{fontWeight:700,color:C.blue,fontSize:12,fontFamily:C.mono}}>{d.title}</div>
            </div>
            <p style={{fontSize:12.5,color:C.sub,lineHeight:1.7,marginBottom:8}}>{d.reason}</p>
            <div style={{background:C.redD,borderRadius:5,padding:"8px 10px",marginBottom:6}}>
              <div style={{fontSize:9,fontWeight:700,color:C.red,textTransform:"uppercase",letterSpacing:1.5,marginBottom:2,fontFamily:C.mono}}>⚡ Consequence</div>
              <p style={{fontSize:12,color:C.text,margin:0,lineHeight:1.6}}>{d.consequence}</p>
            </div>
            <div style={{background:C.greenD,borderRadius:5,padding:"8px 10px"}}>
              <div style={{fontSize:9,fontWeight:700,color:C.green,textTransform:"uppercase",letterSpacing:1.5,marginBottom:2,fontFamily:C.mono}}>✓ Better Alternative</div>
              <p style={{fontSize:12,color:C.text,margin:0,lineHeight:1.6}}>{d.alternative}</p>
            </div>
          </Box>)}
        </div>
        <Alert type="warn" title="The Lesson">{ar.lesson}</Alert>
      </div>}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:20}}>
        <Btn variant="ghost" onClick={onBack}>◀ BACK</Btn>
        {canProceed
          ?<Btn onClick={onNext}>NEXT: ARCHITECTURE ▶</Btn>
          :<span style={{fontSize:12,color:C.muted,fontFamily:C.mono}}>Read all 4 tabs to continue</span>}
      </div>
    </div>
  );
}

// ══ STEP Q2-ARCH: Study the clean architecture (zero threat hints) ═════════
// Students see the C4 diagram for the first time. No badges, no threat overlays.
// They must read all 3 tabs before proceeding.
function StepQ2Arch({ws,onNext,onBack}) {
  const [tab,setTab]=useState(0);
  const [seen,setSeen]=useState(new Set([0]));
  function goTab(i){setTab(i);setSeen(s=>new Set([...s,i]));}
  const canProceed=seen.size>=3;
  return (
    <div className="fu">
      <div style={{display:"flex",gap:12,marginBottom:12,alignItems:"center"}}>
        <div style={{width:44,height:44,borderRadius:5,background:`${C.blue}18`,
          border:`1.5px solid ${C.blue}`,display:"flex",alignItems:"center",justifyContent:"center",
          fontFamily:C.display,fontSize:18,color:C.blue}}>Q2</div>
        <div>
          <div style={{fontFamily:C.display,fontSize:24,color:C.text,letterSpacing:1}}>STUDY THE ARCHITECTURE</div>
          <div style={{fontSize:13,color:C.sub}}>No threat hints yet — learn the system first ({seen.size}/3 tabs read)</div>
        </div>
      </div>
      <Alert type="warn" title="This is the only time you'll see a clean diagram">
        Study it carefully. In the next step you will label trust zones <strong style={{color:C.text}}>from memory</strong>. After that you'll use STRIDE rules to discover threats yourself. The diagram will only reveal threats you've earned.
      </Alert>
      <Tabs tabs={["C4 Diagram","Components & Flows","Trust Boundaries"]} active={tab} onChange={goTab}/>
      {tab===0&&<div>
        <C4Diagram ws={ws} mode="clean"/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginTop:12}}>
          {[{s:"◇ Actor / External",c:C.sub,d:"Outside your control. Z0 — untrusted by definition."},
            {s:"▢ Service",c:C.accent,d:"Your team's services. Can have all 6 STRIDE categories."},
            {s:"⊟ Data Store",c:C.amber,d:"Where data persists. Always Tampering + Info Disclosure risk."},
          ].map(e=><Box key={e.s} style={{padding:"10px 14px"}}>
            <div style={{fontWeight:700,color:e.c,fontSize:12,marginBottom:4,fontFamily:C.mono}}>{e.s}</div>
            <p style={{fontSize:12,color:C.sub,margin:0,lineHeight:1.6}}>{e.d}</p>
          </Box>)}
        </div>
      </div>}
      {tab===1&&<div>
        <Alert type="concept">Every arrow is a data flow. Flows crossing trust boundaries are where STRIDE threats most commonly appear.</Alert>
        <div style={{overflowX:"auto",marginBottom:12}}>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:12.5,fontFamily:C.mono}}>
            <thead><tr style={{background:C.raised}}>{["Component","Type","Controls Data?","Role"].map(h=><th key={h} style={{padding:"9px 12px",textAlign:"left",color:C.sub,fontSize:10,textTransform:"uppercase",letterSpacing:1.5}}>{h}</th>)}</tr></thead>
            <tbody>{ws.components.map((c,i)=><tr key={c.name} style={{background:i%2===0?C.card:C.panel,borderBottom:`1px solid ${C.border}`}}>
              <td style={{padding:"9px 12px",color:C.text,fontWeight:700}}>{c.name}</td>
              <td style={{padding:"9px 12px"}}><Tag color={c.type==="external"?C.sub:c.type==="store"?C.amber:C.accent}>{c.type}</Tag></td>
              <td style={{padding:"9px 12px",color:c.type!=="external"?C.green:C.red,fontSize:12}}>{c.type!=="external"?"Yes":"No"}</td>
              <td style={{padding:"9px 12px",color:C.sub,fontSize:12}}>{c.desc}</td>
            </tr>)}</tbody>
          </table>
        </div>
        <div style={{overflowX:"auto"}}>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:12.5,fontFamily:C.mono}}>
            <thead><tr style={{background:C.raised}}>{["From","To","Data","Protocol"].map(h=><th key={h} style={{padding:"9px 12px",textAlign:"left",color:C.sub,fontSize:10,textTransform:"uppercase",letterSpacing:1.5}}>{h}</th>)}</tr></thead>
            <tbody>{ws.flows.map((f,i)=><tr key={i} style={{background:i%2===0?C.card:C.panel,borderBottom:`1px solid ${C.border}`}}>
              <td style={{padding:"9px 12px",color:C.text,fontWeight:600}}>{f.src}</td>
              <td style={{padding:"9px 12px",color:C.accent}}>→ {f.dst}</td>
              <td style={{padding:"9px 12px",color:C.sub}}>{f.data}</td>
              <td style={{padding:"9px 12px"}}><Tag color={C.blue}>{f.proto}</Tag></td>
            </tr>)}</tbody>
          </table>
        </div>
      </div>}
      {tab===2&&<div>
        <Alert type="warn" title="Trust boundaries are where attackers operate — you'll label these in the next step"/>
        {ws.boundaries.map((b,i)=><Box key={b.name} style={{marginBottom:10,borderLeft:`3px solid ${C.purple}`}}>
          <div style={{fontWeight:700,color:C.purple,marginBottom:6,fontFamily:C.mono,fontSize:12,textTransform:"uppercase"}}>{b.name}</div>
          <div style={{display:"flex",gap:10,marginBottom:6}}>
            <Tag color={C.green}>{b.from}</Tag><span style={{color:C.muted,fontFamily:C.mono}}>→</span><Tag color={C.red}>{b.to}</Tag>
          </div>
          <p style={{fontSize:13,color:C.sub,lineHeight:1.7,margin:0}}>{b.risk}</p>
        </Box>)}
      </div>}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:20}}>
        <Btn variant="ghost" onClick={onBack}>◀ BACK</Btn>
        {canProceed
          ?<Btn onClick={onNext}>NEXT: LABEL THE ZONES ▶</Btn>
          :<span style={{fontSize:12,color:C.muted,fontFamily:C.mono}}>Read all 3 tabs to continue</span>}
      </div>
    </div>
  );
}

// ══ STEP Q2-ZONES: Blind Zone Labelling ══════════════════════════════════
// The diagram is shown CLEAN — no zone badges visible during labelling.
// After submission, zones are revealed with explanations.
// Must score ≥40% to proceed (learning, not a test).
function StepQ2Zones({ws,onNext,onBack}) {
  // Three phases: theory → label → results
  const [phase, setPhase] = useState("theory");
  const [answers, setAnswers] = useState({});
  const zoneOpts = Object.keys(C.zones);
  const correct = ws.components.filter(c => answers[c.name] === c.zone).length;
  const pct = Math.round(correct / ws.components.length * 100);
  const allAnswered = Object.keys(answers).length === ws.components.length;
  const canProceed = phase === "results" && pct >= 40;

  return (
    <div className="fu">
      {/* Header + phase progress pills */}
      <div style={{display:"flex",gap:12,marginBottom:16,alignItems:"center"}}>
        <div style={{width:44,height:44,borderRadius:5,background:`${C.purple}18`,
          border:`1.5px solid ${C.purple}`,display:"flex",alignItems:"center",justifyContent:"center",
          fontFamily:C.display,fontSize:18,color:C.purple}}>③</div>
        <div>
          <div style={{fontFamily:C.display,fontSize:24,color:C.text,letterSpacing:1}}>TRUST ZONE LABELLING</div>
          <div style={{display:"flex",gap:6,marginTop:5}}>
            {["Theory","Label","Results"].map((p,i) => {
              const key = ["theory","label","results"][i];
              const idx = ["theory","label","results"].indexOf(phase);
              const isDone = i < idx;
              const isActive = key === phase;
              return <div key={p} style={{padding:"2px 10px",borderRadius:4,fontSize:9,fontWeight:700,
                fontFamily:C.mono,textTransform:"uppercase",letterSpacing:1,
                background:isActive?C.accent:isDone?C.greenD:C.raised,
                color:isActive?"#000":isDone?C.green:C.muted,
                border:`1px solid ${isActive?C.accent:isDone?C.green:C.border}`}}>
                {i+1}. {p}
              </div>;
            })}
          </div>
        </div>
      </div>

      {/* ══ PHASE 1: THEORY ══════════════════════════════════════════════ */}
      {phase === "theory" && (
        <div>
          <Alert type="concept" title="Why zones come before threats">
            In STRIDE, threat categories are <strong style={{color:C.text}}>mechanically derived from zone relationships</strong>.
            A flow rising from Z0→Z7 always carries Tampering risk. A flow descending always carries Information Disclosure risk.
            <strong style={{color:C.accent}}> Wrong zones = wrong threats.</strong> Get this right before you look for threats.
          </Alert>

          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(240px,1fr))",gap:10,marginBottom:16}}>
            {Object.entries(C.zones).map(([z,zc]) => (
              <div key={z} style={{background:zc.bg,border:`1.5px solid ${zc.c}`,borderRadius:8,padding:"12px 14px"}}>
                <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:8}}>
                  <div style={{width:28,height:28,borderRadius:14,background:zc.c,display:"flex",
                    alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:900,
                    color:"#000",fontFamily:C.mono,flexShrink:0}}>{zc.badge}</div>
                  <span style={{fontSize:13,color:zc.c,fontFamily:C.mono,fontWeight:700}}>{z}</span>
                </div>
                <div style={{fontSize:12,color:C.sub,lineHeight:1.65}}>
                  {z==="Not in Control" && "External parties, vendors, end users. Your team has no ability to enforce controls on these entities. Always Z0."}
                  {z==="Minimal Trust" && "Browser-side or client-controlled code. Your team wrote it but cannot trust the runtime — the user can modify it."}
                  {z==="Standard" && "Your application services — your team builds and operates them. All 6 STRIDE categories can apply."}
                  {z==="Elevated" && "Higher-value business services or staging areas for sensitive data. Stricter access controls required."}
                  {z==="Critical" && "PII, payment data, secrets. Highest breach impact. Every flow in or out requires explicit justification."}
                  {z==="Max Security" && "Clinical or safety-critical data. Any unauthorised access is a regulatory violation with potential patient harm."}
                </div>
              </div>
            ))}
          </div>

          <Alert type="info" title="Ask these three questions before labelling each component">
            <strong style={{color:C.blue}}>1. Who controls this?</strong> — Your team / a vendor / the end-user?<br/>
            <strong style={{color:C.blue}}>2. What data flows through it?</strong> — PII? Payment? Health? Anonymous?<br/>
            <strong style={{color:C.blue}}>3. What is the breach impact?</strong> — Regulatory fine? Revenue loss? Patient harm?
          </Alert>

          <Box style={{marginTop:12}}>
            <div style={{fontSize:11,fontWeight:700,color:C.text,fontFamily:C.mono,
              textTransform:"uppercase",letterSpacing:1.5,marginBottom:10}}>Zone direction → STRIDE category</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8}}>
              {[["↑ Flow rises","T","Tampering — lower-trust caller can corrupt higher-trust target"],
                ["↓ Flow descends","I","Info Disclosure — data flows to less-controlled environment"],
                ["Z0 source","D","DoS — no constraints on untrusted callers"],
                ["Z0 reachable","S","Spoofing — attacker can reach and impersonate"],
                ["S + T on node","R","Repudiation — perform action + deny it"],
                ["Adjacent lower zone","E","EoP — exploit trust from neighbouring component"],
              ].map(([r,cat,ex]) => (
                <div key={cat} style={{background:C.raised,borderRadius:6,padding:"8px 10px",border:`1px solid ${C[cat]}33`}}>
                  <div style={{display:"flex",gap:6,alignItems:"center",marginBottom:4}}>
                    <span style={{width:22,height:22,borderRadius:4,background:`${C[cat]}20`,
                      border:`1.5px solid ${C[cat]}`,display:"flex",alignItems:"center",justifyContent:"center",
                      fontSize:12,fontWeight:900,color:C[cat],fontFamily:C.display,flexShrink:0}}>{cat}</span>
                    <span style={{fontSize:11,fontWeight:700,color:C.text,fontFamily:C.mono}}>{r}</span>
                  </div>
                  <div style={{fontSize:11,color:C.muted,lineHeight:1.5}}>{ex}</div>
                </div>
              ))}
            </div>
          </Box>

          <div style={{display:"flex",justifyContent:"space-between",marginTop:20}}>
            <Btn variant="ghost" onClick={onBack}>◀ BACK</Btn>
            <Btn onClick={() => setPhase("label")}>I UNDERSTAND — START LABELLING ▶</Btn>
          </div>
        </div>
      )}

      {/* ══ PHASE 2: LABEL ════════════════════════════════════════════════ */}
      {phase === "label" && (
        <div>
          <Alert type="warn" title="Diagram hidden — label from memory">
            The architecture diagram is hidden during this exercise. Use the zone definitions and the three questions.
            You can go back to review theory at any time.
          </Alert>

          {/* Compact zone reference strip */}
          <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:16,padding:"10px 14px",
            background:C.raised,borderRadius:6,border:`1px solid ${C.border}`}}>
            <span style={{fontSize:9,fontWeight:700,color:C.muted,fontFamily:C.mono,
              textTransform:"uppercase",letterSpacing:1.5,alignSelf:"center",marginRight:4}}>ZONES:</span>
            {Object.entries(C.zones).map(([z,zc]) => (
              <div key={z} style={{display:"flex",gap:4,alignItems:"center",padding:"3px 8px",
                background:zc.bg,border:`1px solid ${zc.c}44`,borderRadius:4}}>
                <span style={{fontSize:9,fontWeight:900,color:zc.c,fontFamily:C.mono}}>{zc.badge}</span>
                <span style={{fontSize:10,color:zc.c,fontFamily:C.mono}}>{z}</span>
              </div>
            ))}
          </div>

          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(230px,1fr))",gap:10}}>
            {ws.components.map(comp => {
              const ans = answers[comp.name];
              return (
                <div key={comp.name} style={{background:C.card,
                  border:`1.5px solid ${ans ? C.accent : C.border}`,
                  borderRadius:8,padding:"12px 14px",transition:"border-color .15s"}}>
                  <div style={{fontWeight:700,color:C.text,marginBottom:2,fontFamily:C.mono,fontSize:13}}>{comp.name}</div>
                  <div style={{fontSize:11,color:C.muted,marginBottom:10,lineHeight:1.5}}>{comp.desc}</div>
                  <select value={ans || ""} onChange={e => setAnswers(a => ({...a,[comp.name]:e.target.value}))}
                    style={{width:"100%",padding:"8px 10px",background:C.panel,
                      border:`1px solid ${ans ? C.accent : C.border}`,
                      borderRadius:4,color:C.text,fontSize:12.5,fontFamily:C.body}}>
                    <option value="">— select zone —</option>
                    {zoneOpts.map(z => <option key={z} value={z}>{z}</option>)}
                  </select>
                  {ans && (
                    <div style={{marginTop:5,fontSize:10,color:C.accent,fontFamily:C.mono}}>
                      ✓ {ans}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div style={{display:"flex",justifyContent:"space-between",marginTop:16,alignItems:"center"}}>
            <Btn variant="ghost" onClick={() => setPhase("theory")}>◀ REVIEW THEORY</Btn>
            <div style={{display:"flex",gap:10,alignItems:"center"}}>
              <span style={{fontSize:11,color:C.muted,fontFamily:C.mono}}>
                {Object.keys(answers).length}/{ws.components.length} labelled
              </span>
              <Btn onClick={() => setPhase("results")} disabled={!allAnswered}>
                {allAnswered ? "CHECK ANSWERS ▶" : "Label all components first"}
              </Btn>
            </div>
          </div>
        </div>
      )}

      {/* ══ PHASE 3: RESULTS ══════════════════════════════════════════════ */}
      {phase === "results" && (
        <div>
          <Alert type={pct>=80?"success":pct>=50?"warn":"info"}
            title={`${correct}/${ws.components.length} correct — ${pct}%`}>
            {pct>=80 ? "Excellent zone analysis. Your STRIDE derivation will be accurate." :
             pct>=50 ? "Good attempt. Review the incorrect zones — the reasoning matters more than the answer." :
             "Study the zone rationale below carefully. The next step shows how zones drive threat discovery."}
            {" "}40% required to continue.
          </Alert>

          {/* NOW reveal the annotated architecture diagram */}
          <div style={{marginBottom:16}}>
            <div style={{fontSize:10,fontWeight:700,color:C.muted,fontFamily:C.mono,
              textTransform:"uppercase",letterSpacing:1.5,marginBottom:8}}>◈ Correct Zone Annotations</div>
            <C4Diagram ws={ws} mode="zones"/>
          </div>

          {/* Per-component results grid */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(230px,1fr))",gap:10,marginBottom:14}}>
            {ws.components.map(comp => {
              const ans = answers[comp.name];
              const isOk = ans === comp.zone;
              const zc = C.zones[comp.zone];
              return (
                <div key={comp.name} style={{background:isOk?C.greenD:C.redD,
                  border:`1.5px solid ${isOk?C.green:C.red}`,borderRadius:8,padding:"12px 14px"}}>
                  <div style={{fontWeight:700,color:C.text,marginBottom:6,fontFamily:C.mono,fontSize:12}}>{comp.name}</div>
                  <div style={{display:"flex",gap:6,marginBottom:4,flexWrap:"wrap",alignItems:"center"}}>
                    <span style={{fontSize:10,color:C.muted,fontFamily:C.mono}}>Your answer:</span>
                    {ans
                      ? <Tag color={C.zones[ans]?.c||C.muted} style={{fontSize:9}}>{ans}</Tag>
                      : <span style={{color:C.red,fontSize:10,fontFamily:C.mono}}>No answer</span>}
                  </div>
                  {!isOk && (
                    <div style={{display:"flex",gap:6,marginBottom:6,flexWrap:"wrap",alignItems:"center"}}>
                      <span style={{fontSize:10,color:C.muted,fontFamily:C.mono}}>Correct:</span>
                      <Tag color={zc.c} style={{fontSize:9}}>{zc.badge} {comp.zone}</Tag>
                    </div>
                  )}
                  <div style={{fontSize:11,fontWeight:700,color:isOk?C.green:C.red,fontFamily:C.mono,marginBottom:isOk?0:4}}>
                    {isOk ? "✓ Correct" : "✗ Incorrect"}
                  </div>
                  {!isOk && (
                    <div style={{fontSize:11.5,color:C.sub,lineHeight:1.6,background:C.panel,
                      borderRadius:4,padding:"6px 10px"}}>
                      Score {comp.score} — {comp.desc}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div style={{display:"flex",justifyContent:"space-between",marginTop:4}}>
            <Btn variant="ghost" onClick={() => setPhase("label")}>◀ REVISE ANSWERS</Btn>
            {canProceed
              ? <Btn onClick={onNext}>NEXT: DISCOVER THREATS ▶</Btn>
              : <span style={{fontSize:12,color:C.muted,fontFamily:C.mono,paddingTop:8}}>
                  Score 40%+ to continue (currently {pct}%)
                </span>
            }
          </div>
        </div>
      )}
    </div>
  );
}


// ══ STEP Q2-STRIDE: Progressive Threat Discovery ══════════════════════════
// The diagram starts CLEAN. Each correctly analysed threat reveals itself
// on the diagram as an orange badge. Students see the diagram "light up"
// as they discover threats — reinforcing the connection between zones and threats.
function StepQ2Stride({ws,answers,setAnswers,totalScore,maxScore,onNext,onBack}) {
  const analyzed=new Set(answers.map(a=>a.id));
  const revealedIds=analyzed; // only show found threats on diagram
  const remaining=ws.threats.filter(t=>!analyzed.has(t.id));
  const [selId,setSelId]=useState(remaining[0]?.id||"");
  const [form,setForm]=useState({stride:"",likelihood:"Low",impactR:"Low",controls:[]});
  const [feedback,setFeedback]=useState(null);
  const [tab,setTab]=useState(0);
  const threat=ws.threats.find(t=>t.id===selId);
  const pct=maxScore>0?Math.round(totalScore/maxScore*100):0;

  function submit(){
    if(!threat||!form.stride) return;
    let score=0; const fb=[];
    if(form.stride===threat.stride){score+=3;fb.push({ok:true,msg:"+3 Correct STRIDE category"});}
    else fb.push({ok:false,msg:`✗ STRIDE: correct is "${threat.stride}"`});
    if(form.likelihood===threat.likelihood){score+=1;fb.push({ok:true,msg:"+1 Likelihood correct"});}
    else fb.push({ok:false,msg:`✗ Likelihood: correct is "${threat.likelihood}"`});
    if(form.impactR===threat.impact_rating){score+=1;fb.push({ok:true,msg:"+1 Impact correct"});}
    else fb.push({ok:false,msg:`✗ Impact: correct is "${threat.impact_rating}"`});
    const correct=new Set(threat.controls_correct||[]);
    const wrong=new Set(threat.controls_wrong||[]);
    const sel=new Set(form.controls);
    const cC=[...correct].filter(m=>sel.has(m)).length;
    const cW=[...wrong].filter(m=>sel.has(m)).length;
    score+=Math.max(0,cC-cW);
    fb.push({ok:cC>0&&cW===0,msg:`Controls: ${cC}/${correct.size} correct${cW>0?` · ${cW} wrong`:""}`});
    const entry={id:threat.id,score,maxScore:7,feedback:fb,threat};
    setAnswers(prev=>[...prev,entry]);
    setFeedback(entry);
  }

  return (
    <div className="fu">
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
        {[["Found",`${answers.length}/${ws.threats.length}`],["Score",`${totalScore}/${maxScore}`],
          ["Accuracy",`${pct}%`],["Remaining",remaining.length]].map(([l,v])=>(
          <Box key={l} style={{textAlign:"center",padding:"10px 8px"}}>
            <div style={{fontSize:22,fontWeight:900,color:C.accent,fontFamily:C.display,letterSpacing:1}}>{v}</div>
            <div style={{fontSize:9,color:C.muted,marginTop:2,textTransform:"uppercase",letterSpacing:1.5,fontFamily:C.mono}}>{l}</div>
          </Box>
        ))}
      </div>

      <Tabs tabs={["Discover","STRIDE Rules","Threat Grammar"]} active={tab} onChange={setTab}/>

      {tab===0&&(feedback?(
        <div>
          {/* Diagram now shows the newly found threat */}
          <C4Diagram ws={ws} mode="threats" revealedThreats={revealedIds}
            selectedThreat={feedback.threat}/>
          <Alert type="info" style={{marginTop:8,marginBottom:4}}
            title={`${feedback.threat.id} revealed on diagram — orange badge shows where it lives`}/>
          <Box style={{marginTop:8}}>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:10}}>
              {feedback.feedback.map((f,i)=>(
                <div key={i} style={{padding:"6px 10px",background:f.ok?C.greenD:C.redD,borderRadius:4,
                  fontSize:12,color:f.ok?C.green:C.red,fontFamily:C.mono,border:`1px solid ${f.ok?C.green:C.red}33`}}>{f.msg}</div>
              ))}
            </div>
            <Alert type="success" title="Expert threat statement">
              <div style={{fontFamily:C.mono,fontSize:12.5,color:C.text,lineHeight:1.8,
                padding:"6px 10px",background:C.panel,borderRadius:5,marginTop:4}}>{feedback.threat.composed}</div>
            </Alert>
            <p style={{fontSize:13,color:C.sub,lineHeight:1.75,marginTop:8}}>{feedback.threat.explanation}</p>
          </Box>
          {remaining.length>0
            ?<Btn onClick={()=>{setFeedback(null);setSelId(remaining[0]?.id||"");
                setForm({stride:"",likelihood:"Low",impactR:"Low",controls:[]});}}
              style={{marginTop:12}}>FIND NEXT THREAT ▶</Btn>
            :<Alert type="success" style={{marginTop:12}}>All {ws.threats.length} threats found. Proceed to attack path analysis.</Alert>}
        </div>
      ):(
        <div>
          {/* Progressive diagram — only reveals already-found threats */}
          <C4Diagram ws={ws}
            mode={revealedIds.size>0?"threats":"clean"}
            revealedThreats={revealedIds}/>
          {revealedIds.size===0
            ?<Alert type="info" style={{marginTop:8}} title="Diagram starts clean">
              As you correctly identify threats, they'll appear as orange badges on the diagram above.
            </Alert>
            :<Alert type="info" style={{marginTop:8,marginBottom:4}}
              title={`${revealedIds.size} threat${revealedIds.size>1?"s":""} found — diagram updating`}/>
          }
          {threat&&(
            <Box style={{marginTop:12,borderLeft:`3px solid ${C[threat.stride?.[0]]||C.accent}`}}>
              <div style={{fontWeight:700,color:C.text,marginBottom:6,fontFamily:C.mono,fontSize:12}}>
                SCENARIO {threat.id}</div>
              <p style={{fontSize:13,color:C.sub,lineHeight:1.75,marginBottom:12}}>{threat.stride_rule}</p>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                <div>
                  <label style={{display:"block",fontSize:10,fontWeight:700,color:C.muted,
                    textTransform:"uppercase",letterSpacing:1.5,marginBottom:4,fontFamily:C.mono}}>STRIDE category *</label>
                  <select value={form.stride} onChange={e=>setForm(p=>({...p,stride:e.target.value}))}
                    style={{width:"100%",padding:"8px 10px",background:C.panel,
                      border:`1px solid ${C.border}`,borderRadius:4,color:C.text,fontSize:13,
                      fontFamily:C.body,marginBottom:10}}>
                    <option value="">— apply zone-direction rules —</option>
                    {["Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"].map(s=><option key={s} value={s}>{s}</option>)}
                  </select>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                    {[["likelihood","Likelihood"],["impactR","Impact"]].map(([k,l])=>(
                      <div key={k}>
                        <label style={{display:"block",fontSize:10,fontWeight:700,color:C.muted,
                          textTransform:"uppercase",letterSpacing:1.5,marginBottom:4,fontFamily:C.mono}}>{l}</label>
                        <select value={form[k]} onChange={e=>setForm(p=>({...p,[k]:e.target.value}))}
                          style={{width:"100%",padding:"7px 10px",background:C.panel,
                            border:`1px solid ${C.border}`,borderRadius:4,color:C.text,fontSize:12.5,fontFamily:C.body}}>
                          {["Low","Medium","High","Critical"].map(v=><option key={v} value={v}>{v}</option>)}
                        </select>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <label style={{display:"block",fontSize:10,fontWeight:700,color:C.muted,
                    textTransform:"uppercase",letterSpacing:1.5,marginBottom:4,fontFamily:C.mono}}>Mitigations</label>
                  {[...(threat.controls_correct||[]),...(threat.controls_wrong||[])].sort().map(m=>{
                    const on=form.controls.includes(m);
                    return <div key={m}
                      onClick={()=>setForm(f=>({...f,controls:on?f.controls.filter(x=>x!==m):[...f.controls,m]}))}
                      style={{padding:"6px 10px",margin:"3px 0",background:on?C.blueD:C.panel,
                        border:`1px solid ${on?C.blue:C.border}`,borderRadius:4,cursor:"pointer",
                        fontSize:11.5,color:on?C.blue:C.sub,transition:"all .12s",userSelect:"none",lineHeight:1.4}}>
                      <span style={{marginRight:8,fontFamily:C.mono,fontSize:10}}>{on?"☑":"☐"}</span>{m}
                    </div>;
                  })}
                </div>
              </div>
              {remaining.length>1&&(
                <div style={{marginTop:12}}>
                  <label style={{fontSize:10,fontWeight:700,color:C.muted,textTransform:"uppercase",
                    letterSpacing:1.5,marginBottom:4,fontFamily:C.mono,display:"block"}}>SCENARIO</label>
                  <select value={selId} onChange={e=>{setSelId(e.target.value);setForm({stride:"",likelihood:"Low",impactR:"Low",controls:[]});}}
                    style={{width:"100%",padding:"7px 10px",background:C.panel,
                      border:`1px solid ${C.border}`,borderRadius:4,color:C.text,fontSize:12.5,fontFamily:C.body}}>
                    {remaining.map(t=><option key={t.id} value={t.id}>{t.id}: {t.stride_rule?.slice(0,65)}</option>)}
                  </select>
                </div>
              )}
              <Btn onClick={submit} disabled={!form.stride} style={{marginTop:12}}>SUBMIT ANALYSIS</Btn>
            </Box>
          )}
          {remaining.length===0&&<Alert type="success">All threats identified.</Alert>}
        </div>
      ))}

      {tab===1&&(
        <div>
          {[{r:"Flow rises (low→high zone)",cat:"T",ex:"SPA Z1 → API Z3: Tampering risk on every upward flow"},
            {r:"Flow descends (high→low zone)",cat:"I",ex:"DB Z7 → API Z3: Information Disclosure on every downward flow"},
            {r:"Z0 source on any flow",cat:"D",ex:"Customer Z0 → SPA: DoS — no constraints on untrusted callers"},
            {r:"Node reachable from Z0",cat:"S",ex:"API reachable via chain from Customer: Spoofing applies"},
            {r:"Both S and T on same node",cat:"R",ex:"API has S + T: Repudiation applies"},
            {r:"Node adjacent to lower-zone node",cat:"E",ex:"API adjacent to SPA Z1: EoP applies"},
          ].map(row=>(
            <div key={row.cat} style={{display:"flex",gap:12,padding:"10px 14px",background:C.card,
              border:`1px solid ${C.border}`,borderLeft:`3px solid ${C[row.cat]}`,borderRadius:6,marginBottom:6}}>
              <div style={{width:28,height:28,borderRadius:4,background:`${C[row.cat]}20`,
                border:`1.5px solid ${C[row.cat]}`,display:"flex",alignItems:"center",justifyContent:"center",
                fontSize:13,fontWeight:900,color:C[row.cat],fontFamily:C.display,flexShrink:0}}>{row.cat}</div>
              <div>
                <div style={{fontWeight:700,color:C.text,fontSize:12.5,marginBottom:3}}>{row.r}</div>
                <div style={{fontSize:11.5,color:C.muted,fontFamily:C.mono}}>{row.ex}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab===2&&(
        <Box>
          <div style={{fontFamily:C.display,fontSize:16,color:C.accent,letterSpacing:1,marginBottom:12}}>THREAT STATEMENT STRUCTURE</div>
          {[{f:"[Threat Source]",c:C.red,d:"WHO is the attacker?",e:"An unauthenticated attacker (Customer, Z0)"},
            {f:"can [Action]",c:C.amber,d:"WHAT do they do?",e:"impersonate a legitimate user"},
            {f:"[Target Asset]",c:C.blue,d:"WHAT are they attacking?",e:"the Node.js API session"},
            {f:"via [Method]",c:C.purple,d:"HOW do they do it?",e:"replaying a stolen JWT obtained via XSS"},
            {f:"resulting in [Impact]",c:C.green,d:"WHAT is the consequence?",e:"gaining full account access"},
          ].map(f=>(
            <div key={f.f} style={{display:"flex",gap:12,padding:"8px 0",borderBottom:`1px solid ${C.border}`}}>
              <code style={{width:165,flexShrink:0,color:f.c,fontFamily:C.mono,fontSize:12,
                background:`${f.c}10`,borderRadius:4,padding:"2px 8px",alignSelf:"flex-start"}}>{f.f}</code>
              <div>
                <div style={{fontSize:12,color:C.sub,marginBottom:2}}>{f.d}</div>
                <div style={{fontSize:12.5,color:C.text,fontFamily:C.mono}}>{f.e}</div>
              </div>
            </div>
          ))}
        </Box>
      )}

      <div style={{display:"flex",justifyContent:"space-between",marginTop:20}}>
        <Btn variant="ghost" onClick={onBack}>◀ BACK</Btn>
        {answers.length>=ws.threats.length
          ?<Btn onClick={onNext}>NEXT: ATTACK PATHS ▶</Btn>
          :<span style={{fontSize:12,color:C.muted,fontFamily:C.mono,paddingTop:8}}>
            Find all {ws.threats.length} threats to continue ({answers.length} found)
          </span>}
      </div>
    </div>
  );
}
function StepQ2Tree({ws,answers,onNext,onBack}) {
  const [tab,setTab]=useState(0);
  const [selPath,setSelPath]=useState(0);
  const [phase,setPhase]=useState("idle");
  const [activeStep,setActiveStep]=useState(-1);
  const [timer,setTimer]=useState(null);

  const paths=ws.attackTree?.paths||[];
  const path=paths[selPath];

  // All threats are now known — show full threat diagram as context
  const allThreatIds=new Set(ws.threats.map(t=>t.id));

  useEffect(()=>()=>{if(timer)clearTimeout(timer);},[timer]);

  function runAttack(){
    setPhase("running"); setActiveStep(0);
    let i=0;
    function next(){
      i++;
      if(i<path.steps.length){const t=setTimeout(()=>{setActiveStep(i);next();},1200);setTimer(t);}
      else{const t=setTimeout(()=>setPhase("done"),900);setTimer(t);}
    }
    const t=setTimeout(()=>next(),1200); setTimer(t);
  }
  function reset(){setPhase("idle");setActiveStep(-1);if(timer)clearTimeout(timer);}

  const diffCol={Easy:C.red,Medium:C.amber,Hard:C.green};

  const nodeColor=(step,idx)=>{
    if(phase==="idle") return C.border;
    if(phase==="running"||phase==="done") return idx<=activeStep||phase==="done"?C.red:C.border;
    if(phase==="stride") return C[step.strideType?.[0]]||C.amber;
    if(phase==="mitigated"){const hasMit=(path.mitigations||[]).some(m=>m.step===step.id);return hasMit?C.green:C.red;}
    return C.border;
  };

  return (
    <div className="fu">
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:12}}>
        <div style={{width:44,height:44,borderRadius:5,background:`${C.red}18`,border:`1.5px solid ${C.red}`,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:C.display,fontSize:20,color:C.red}}>⬢</div>
        <div><div style={{fontFamily:C.display,fontSize:24,color:C.text,letterSpacing:1}}>ATTACK PATH ANALYSIS</div><div style={{fontSize:13,color:C.sub}}>Now you know the threats — see how attackers chain them into goals</div></div>
      </div>
      <Tabs tabs={["What & Why","AND / OR Gates","Attack Simulator","Path Priority"]} active={tab} onChange={setTab}/>

      {tab===0&&(
        <div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
            <Box style={{borderLeft:`3px solid ${C.blue}`}}>
              <div style={{fontWeight:700,color:C.blue,marginBottom:8,fontFamily:C.mono,fontSize:12,textTransform:"uppercase"}}>STRIDE answers: WHAT</div>
              <p style={{fontSize:13.5,color:C.sub,lineHeight:1.75,margin:0}}>STRIDE tells you <em>what categories</em> of threat exist at each component. Systematic and exhaustive. You just did this.</p>
            </Box>
            <Box style={{borderLeft:`3px solid ${C.red}`}}>
              <div style={{fontWeight:700,color:C.red,marginBottom:8,fontFamily:C.mono,fontSize:12,textTransform:"uppercase"}}>Attack Trees answer: HOW</div>
              <p style={{fontSize:13.5,color:C.sub,lineHeight:1.75,margin:0}}>Attack trees show <em>how an attacker chains STRIDE threats together</em> to reach a goal — and where one control blocks the entire path.</p>
            </Box>
          </div>
          <Alert type="concept" title="The Connection">Every node in an attack tree maps to STRIDE threats you found. The tree puts them in context as steps in an attacker's plan. Use the Simulator tab to walk through it live.</Alert>
          <Box style={{marginTop:12}}>
            <div style={{fontWeight:700,color:C.text,marginBottom:10,fontFamily:C.mono,fontSize:12,textTransform:"uppercase"}}>When to use attack trees</div>
            {[{ok:true,t:"After STRIDE — to understand exploitation chains for high-severity threats"},
              {ok:true,t:"When prioritising mitigations — find controls that break the most attack paths"},
              {ok:true,t:"When designing defence-in-depth — AND gates show where multiple controls are needed"},
              {ok:false,t:"Don't build trees for every threat — focus on goal-critical, high-impact paths"},
            ].map((item,i)=><div key={i} style={{display:"flex",gap:8,padding:"5px 0",fontSize:13,color:C.sub,borderBottom:i<3?`1px solid ${C.border}`:"none"}}><span style={{color:item.ok?C.green:C.red,flexShrink:0,fontFamily:C.mono}}>{item.ok?"✓":"✗"}</span>{item.t}</div>)}
          </Box>
        </div>
      )}

      {tab===1&&(
        <div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
            {[{name:"AND Gate",col:C.blue,meaning:"ALL children must succeed for the parent to succeed.",implication:"Add ONE defence at ANY child → entire path blocked. This is where defence-in-depth works.",example:"Account Takeover: must steal password AND bypass MFA. Add MFA → breaks AND → path completely blocked."},
              {name:"OR Gate",col:C.green,meaning:"ANY one child path is sufficient for the parent to succeed.",implication:"You must defend EVERY branch independently. Fixing one OR branch does nothing for the others.",example:"'Get credentials': phishing OR credential stuffing OR MITM. Must defend all three independently."},
            ].map(g=>(
              <Box key={g.name} style={{borderTop:`3px solid ${g.col}`}}>
                <div style={{fontWeight:700,color:g.col,fontFamily:C.display,fontSize:18,letterSpacing:1,marginBottom:8}}>{g.name.toUpperCase()}</div>
                <div style={{marginBottom:8}}><div style={{fontSize:10,fontWeight:700,color:C.muted,textTransform:"uppercase",letterSpacing:1.5,marginBottom:4,fontFamily:C.mono}}>MEANING</div><p style={{fontSize:13.5,color:C.text,lineHeight:1.7,margin:0}}>{g.meaning}</p></div>
                <div style={{background:C.raised,borderRadius:5,padding:"10px 12px",marginBottom:10}}><div style={{fontSize:10,fontWeight:700,color:C.muted,textTransform:"uppercase",letterSpacing:1.5,marginBottom:4,fontFamily:C.mono}}>SECURITY IMPLICATION</div><p style={{fontSize:13,color:C.sub,lineHeight:1.7,margin:0}}>{g.implication}</p></div>
                <div style={{background:`${g.col}18`,borderRadius:5,padding:"8px 12px",border:`1px solid ${g.col}33`}}><div style={{fontSize:10,fontWeight:700,color:g.col,textTransform:"uppercase",letterSpacing:1.5,marginBottom:4,fontFamily:C.mono}}>EXAMPLE</div><p style={{fontSize:12.5,color:C.text,lineHeight:1.6,margin:0,fontFamily:C.mono}}>{g.example}</p></div>
              </Box>
            ))}
          </div>
        </div>
      )}

      {tab===2&&paths.length>0&&(
        <div>
          {/* Path selector */}
          <div style={{display:"flex",gap:8,marginBottom:14,flexWrap:"wrap",alignItems:"center"}}>
            <span style={{fontSize:10,color:C.muted,fontFamily:C.mono}}>SELECT PATH:</span>
            {paths.map((p,i)=>(
              <button key={p.id} onClick={()=>{setSelPath(i);reset();}}
                style={{padding:"6px 14px",background:selPath===i?`${p.priorityCol}20`:C.panel,border:`1.5px solid ${selPath===i?p.priorityCol:C.border}`,borderRadius:5,color:selPath===i?p.priorityCol:C.sub,fontFamily:C.mono,fontSize:11,fontWeight:700,cursor:"pointer"}}>
                {p.label}
              </button>
            ))}
          </div>

          {path&&(
            <div>
              {/* Attack flow diagram */}
              <div style={{background:C.panel,borderRadius:8,border:`1px solid ${C.border}`,padding:"24px 20px",marginBottom:14,overflowX:"auto"}}>
                <div style={{fontSize:10,fontWeight:700,color:C.muted,textTransform:"uppercase",letterSpacing:2,fontFamily:C.mono,marginBottom:16}}>{ws.attackTree.title}</div>
                <div style={{display:"flex",alignItems:"center",gap:0,minWidth:"fit-content"}}>
                  {/* Attacker */}
                  <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4}}>
                    <div style={{width:56,height:56,borderRadius:8,background:phase==="idle"?C.raised:`${C.red}20`,border:`2px solid ${phase==="idle"?C.border:C.red}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:22,transition:"all .4s"}}>🧑‍💻</div>
                    <div style={{fontSize:8,fontFamily:C.mono,color:C.sub,textTransform:"uppercase",textAlign:"center"}}>Attacker</div>
                  </div>

                  {path.steps.map((step,i)=>{
                    const nc=nodeColor(step,i);
                    const isActive=(phase==="running"||phase==="done")&&(i<=activeStep||phase==="done");
                    const isCurrent=phase==="running"&&i===activeStep;
                    const hasMit=(path.mitigations||[]).some(m=>m.step===step.id);
                    return (
                      <div key={step.id} style={{display:"flex",alignItems:"center",gap:0}}>
                        {/* Arrow connector */}
                        <div style={{display:"flex",flexDirection:"column",alignItems:"center",width:52}}>
                          <div style={{width:"100%",height:2,background:isActive?nc:C.border,transition:"all .4s",position:"relative"}}>
                            <div style={{position:"absolute",right:-1,top:-4,width:0,height:0,borderTop:"5px solid transparent",borderBottom:"5px solid transparent",borderLeft:`8px solid ${isActive?nc:C.border}`,transition:"all .4s"}}/>
                          </div>
                          {phase==="mitigated"&&hasMit&&(
                            <div style={{fontSize:7.5,color:C.green,fontFamily:C.mono,marginTop:2,textAlign:"center",lineHeight:1.2}}>🛡 BLOCKED</div>
                          )}
                        </div>
                        {/* Step node */}
                        <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4}}>
                          <div style={{width:90,minHeight:60,borderRadius:8,background:nc===C.border?C.card:`${nc}18`,border:`2px solid ${nc}`,padding:"8px",textAlign:"center",transition:"all .4s",position:"relative",
                            boxShadow:isCurrent?`0 0 18px ${nc}77`:undefined}}>
                            {(phase==="stride"||phase==="mitigated")&&(
                              <div style={{position:"absolute",top:-9,right:-9,background:C[step.strideType?.[0]]||C.amber,borderRadius:10,padding:"1px 6px",fontSize:8,fontWeight:700,color:"#000",fontFamily:C.mono,whiteSpace:"nowrap"}}>{step.strideType?.split(" ")[0]||"?"}</div>
                            )}
                            {phase==="mitigated"&&hasMit&&(
                              <div style={{position:"absolute",top:-9,left:-9,background:C.green,borderRadius:10,padding:"1px 6px",fontSize:8,fontWeight:700,color:"#000",fontFamily:C.mono}}>✓</div>
                            )}
                            <div style={{fontSize:9.5,color:nc===C.border?C.text:nc,fontFamily:C.mono,lineHeight:1.4,marginBottom:3}}>{step.label}</div>
                            <div style={{display:"flex",gap:3,justifyContent:"center",flexWrap:"wrap"}}>
                              <Tag color={diffCol[step.difficulty]||C.muted} style={{fontSize:7,padding:"0 4px"}}>{step.difficulty}</Tag>
                            </div>
                          </div>
                          {step.component&&<div style={{fontSize:8,color:C.muted,fontFamily:C.mono,textAlign:"center",maxWidth:88,lineHeight:1.2}}>{step.component}</div>}
                        </div>
                      </div>
                    );
                  })}

                  {/* Arrow to goal */}
                  <div style={{width:36,height:2,background:phase==="done"||phase==="stride"?C.red:C.border,transition:"all .4s",position:"relative"}}>
                    <div style={{position:"absolute",right:-1,top:-4,width:0,height:0,borderTop:"5px solid transparent",borderBottom:"5px solid transparent",borderLeft:`8px solid ${phase==="done"||phase==="stride"?C.red:C.border}`,transition:"all .4s"}}/>
                  </div>
                  {/* Goal */}
                  <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4}}>
                    <div style={{width:80,minHeight:60,borderRadius:8,background:phase==="done"||phase==="stride"?C.redD:phase==="mitigated"?C.greenD:C.raised,border:`2px solid ${phase==="done"||phase==="stride"?C.red:phase==="mitigated"?C.green:C.border}`,padding:"8px",textAlign:"center",transition:"all .4s"}}>
                      <div style={{fontSize:20,marginBottom:2}}>{phase==="mitigated"?"🛡":"🎯"}</div>
                      <div style={{fontSize:8,fontFamily:C.mono,color:phase==="done"||phase==="stride"?C.red:phase==="mitigated"?C.green:C.sub,lineHeight:1.3}}>{phase==="mitigated"?"BLOCKED":ws.attackTree.goal.slice(0,28)+"..."}</div>
                    </div>
                    <Tag color={path.priorityCol} style={{fontSize:8}}>{path.priority}</Tag>
                  </div>
                </div>

                {/* Gate type */}
                <div style={{marginTop:14,padding:"5px 12px",background:C.raised,borderRadius:5,display:"inline-flex",gap:8,alignItems:"center"}}>
                  <div style={{width:8,height:8,borderRadius:"50%",background:path.gateType==="AND"?C.blue:C.green}}/>
                  <span style={{fontSize:9.5,fontFamily:C.mono,color:C.sub}}>{path.gateType} gate — {path.gateType==="AND"?"ALL steps must succeed — ONE defence breaks the chain":"ANY step achieves the goal — defend ALL branches"}</span>
                </div>
              </div>

              {/* Step detail on animation */}
              {(phase==="running"||phase==="done")&&activeStep>=0&&(
                <Alert type="danger" title={`Step ${activeStep+1}: ${path.steps[activeStep]?.label}`} style={{marginBottom:10}}>
                  <div style={{fontFamily:C.mono,fontSize:12}}>{path.steps[activeStep]?.detail}</div>
                </Alert>
              )}

              {/* STRIDE overlay */}
              {phase==="stride"&&(
                <Alert type="warn" title="STRIDE Mapping — These are the threats you found earlier" style={{marginBottom:10}}>
                  <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:8,marginTop:8}}>
                    {path.steps.map(step=>(
                      <div key={step.id} style={{background:C.raised,borderRadius:5,padding:"8px 12px",border:`1px solid ${C[step.strideType?.[0]]||C.amber}33`}}>
                        <div style={{fontSize:9,fontWeight:700,color:C[step.strideType?.[0]]||C.amber,fontFamily:C.mono,marginBottom:3}}>{step.strideType} → {step.strideId}</div>
                        <div style={{fontSize:11.5,color:C.sub}}>{step.label}</div>
                      </div>
                    ))}
                  </div>
                </Alert>
              )}

              {/* Mitigation overlay */}
              {phase==="mitigated"&&(
                <Alert type="success" title="Mitigations Applied — Path Blocked" style={{marginBottom:10}}>
                  {(path.mitigations||[]).map((m,i)=>(
                    <div key={i} style={{display:"flex",gap:10,alignItems:"flex-start",background:C.greenD,borderRadius:5,padding:"8px 12px",border:`1px solid ${C.green}33`,marginTop:6}}>
                      <span style={{color:C.green,fontSize:14,flexShrink:0}}>🛡</span>
                      <div>
                        <div style={{fontSize:9,fontWeight:700,color:C.green,fontFamily:C.mono,marginBottom:2}}>BLOCKS STEP {m.step}</div>
                        <div style={{fontSize:13,color:C.text,lineHeight:1.5}}>{m.control}</div>
                      </div>
                    </div>
                  ))}
                  <div style={{marginTop:8,fontSize:11.5,color:C.muted,fontFamily:C.mono}}>
                    {path.gateType==="AND"?"AND gate: ONE mitigation here is enough to block the entire path. Both = defence-in-depth.":"OR gate: each branch needs its own mitigation — fixing one doesn't help the others."}
                  </div>
                </Alert>
              )}

              {/* Simulator controls */}
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                {phase==="idle"&&<Btn onClick={runAttack} variant="danger" style={{fontSize:11}}>▶ RUN ATTACK</Btn>}
                {phase==="running"&&<Btn variant="ghost" onClick={reset} style={{fontSize:11}}>⟳ Reset</Btn>}
                {phase==="done"&&<><Btn onClick={()=>setPhase("stride")} style={{fontSize:11}}>◈ MAP TO STRIDE</Btn><Btn variant="ghost" onClick={reset} style={{fontSize:11}}>⟳ Reset</Btn></>}
                {phase==="stride"&&<><Btn onClick={()=>setPhase("mitigated")} variant="success" style={{fontSize:11}}>🛡 APPLY MITIGATIONS</Btn><Btn variant="ghost" onClick={reset} style={{fontSize:11}}>⟳ Reset</Btn></>}
                {phase==="mitigated"&&<Btn variant="ghost" onClick={reset} style={{fontSize:11}}>⟳ Reset</Btn>}
              </div>
            </div>
          )}
        </div>
      )}

      {tab===3&&(
        <div>
          <Alert type="danger" title="Prioritisation Rule: Find the Cheapest Attacker Path">
            ① Most <strong style={{color:C.red}}>Easy leaf nodes</strong> — cheapest for attacker<br/>
            ② Fewest <strong style={{color:C.red}}>AND gates</strong> — fewest points where defences could block<br/>
            ③ Most <strong style={{color:C.red}}>OR gates</strong> — most flexibility for the attacker
          </Alert>
          <Box>
            {paths.map(p=>(
              <div key={p.id} style={{display:"flex",gap:12,padding:"10px 14px",background:C.raised,borderRadius:6,marginBottom:8,borderLeft:`3px solid ${p.priorityCol}`}}>
                <div style={{flex:1}}>
                  <div style={{fontWeight:700,color:p.priorityCol,fontSize:13,marginBottom:4}}>{p.label}</div>
                  <div style={{display:"flex",gap:8,marginBottom:6}}>
                    <Tag color={C.muted}>{p.gateType} gate</Tag>
                    <Tag color={C.red}>{p.steps.filter(s=>s.difficulty==="Easy").length}× Easy</Tag>
                    <Tag color={p.priorityCol}>{p.priority} PRIORITY</Tag>
                  </div>
                  <div style={{fontSize:12.5,color:C.sub,lineHeight:1.6}}>{p.gateType==="AND"?"AND gate: add any ONE control at any step to block this path entirely.":"OR gate: every branch must be defended independently — partial fixes don't help."}</div>
                </div>
              </div>
            ))}
          </Box>
        </div>
      )}

      <div style={{display:"flex",justifyContent:"space-between",marginTop:20}}>
        <Btn variant="ghost" onClick={onBack}>◀ BACK</Btn>
        <Btn onClick={onNext}>NEXT: Q3 — MITIGATIONS ▶</Btn>
      </div>
    </div>
  );
}

// ══ STEP Q3: Mitigations — Full Threat Map Now Earned ════════════════════
// This is the first time students see the FULL diagram with ALL threats visible.
// They've earned this view by discovering threats themselves.
function StepQ3({ws,threatAnswers,onNext,onBack}) {
  const [sel,setSel]=useState(ws.threats[0]?.id||"");
  const [showMitDfd,setShowMitDfd]=useState(false);
  const [detailThreat,setDetailThreat]=useState(null);
  const threat=ws.threats.find(t=>t.id===sel);
  const allIds=new Set(ws.threats.map(t=>t.id));

  return (
    <div className="fu">
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:12}}>
        <div style={{width:44,height:44,borderRadius:5,background:`${C.amber}18`,border:`1.5px solid ${C.amber}`,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:C.display,fontSize:18,color:C.amber}}>Q3</div>
        <div><div style={{fontFamily:C.display,fontSize:24,color:C.text,letterSpacing:1}}>WHAT ARE WE GOING TO DO ABOUT IT?</div><div style={{fontSize:13,color:C.sub}}>You've found all threats — now the full threat map is yours</div></div>
      </div>
      <Alert type="success" title="Full diagram unlocked">You identified all {ws.threats.length} threats through STRIDE analysis. The complete threat map is now available — all components labelled, all threat paths visible.</Alert>

      {/* Full threat+mitigation diagram — earned view */}
      <div style={{marginBottom:12}}>
        <div style={{display:"flex",gap:8,marginBottom:8,alignItems:"center"}}>
          <Btn variant={!showMitDfd?"primary":"ghost"} onClick={()=>setShowMitDfd(false)} style={{fontSize:10,padding:"5px 12px"}}>Threat Map</Btn>
          <Btn variant={showMitDfd?"success":"ghost"} onClick={()=>setShowMitDfd(true)} style={{fontSize:10,padding:"5px 12px"}}>✓ Mitigation Map</Btn>
          <span style={{fontSize:10,color:C.muted,fontFamily:C.mono}}>Click any component or flow to inspect</span>
        </div>
        <C4Diagram ws={ws} mode={showMitDfd?"mitigations":"threats"} revealedThreats={allIds}
          showMitigations={showMitDfd}
          selectedThreat={threat}
          onNodeClick={(c,threats)=>{if(threats.length){setSel(threats[0].id);setDetailThreat(threats[0]);}}}
          onFlowClick={t=>{setSel(t.id);setDetailThreat(t);}}/>
        {detailThreat&&<ThreatDetailPanel threat={detailThreat} showMitigations={showMitDfd} onClose={()=>setDetailThreat(null)}/>}
      </div>

      <Box style={{marginBottom:12}}>
        <div style={{fontWeight:700,color:C.text,marginBottom:10,fontFamily:C.mono,fontSize:12,textTransform:"uppercase"}}>Four Response Strategies</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
          {[{s:"Mitigate",c:C.green,d:"Add controls that reduce likelihood or impact."},
            {s:"Eliminate",c:C.blue,d:"Remove the feature or component that creates the threat."},
            {s:"Transfer",c:C.amber,d:"Move responsibility to insurance, vendor, or contractual obligation."},
            {s:"Accept",c:C.muted,d:"Consciously decide the risk is within tolerance. Document who owns it."},
          ].map(x=><div key={x.s} style={{background:C.raised,borderRadius:6,padding:"10px 12px",border:`1px solid ${x.c}33`}}>
            <div style={{fontWeight:700,color:x.c,fontSize:13,marginBottom:6,fontFamily:C.mono}}>{x.s}</div>
            <p style={{fontSize:12,color:C.sub,margin:0,lineHeight:1.6}}>{x.d}</p>
          </div>)}
        </div>
      </Box>

      <div style={{display:"flex",gap:10,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
        <label style={{fontSize:10,fontWeight:700,color:C.muted,textTransform:"uppercase",letterSpacing:2,fontFamily:C.mono}}>THREAT:</label>
        <select value={sel} onChange={e=>setSel(e.target.value)} style={{padding:"8px 12px",background:C.panel,border:`1px solid ${C.border}`,borderRadius:4,color:C.text,fontSize:13,fontFamily:C.body,flex:1,minWidth:280}}>
          {ws.threats.map(t=><option key={t.id} value={t.id}>{t.id}: {t.stride} — {t.composed?.slice(0,50)}...</option>)}
        </select>
      </div>

      {threat&&(
        <div>
          <Box style={{marginBottom:10,borderLeft:`3px solid ${C[threat.stride[0]]||C.accent}`}}>
            <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:10}}>
              <Tag color={C[threat.stride[0]]||C.accent}>{threat.stride}</Tag>
              <Tag color={C.amber}>{threat.owasp}</Tag>
              <Tag color={threat.impact_rating==="Critical"?C.red:C.amber}>Likelihood: {threat.likelihood} · Impact: {threat.impact_rating}</Tag>
            </div>
            <div style={{fontFamily:C.mono,fontSize:12.5,color:C.text,lineHeight:1.8,padding:"8px 12px",background:C.panel,borderRadius:5,marginBottom:10}}>{threat.composed}</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
              <Box style={{padding:"10px 12px",background:C.greenD,border:`1px solid ${C.green}22`}}>
                <div style={{fontSize:9,fontWeight:700,color:C.green,textTransform:"uppercase",letterSpacing:2,marginBottom:6,fontFamily:C.mono}}>✓ Correct Controls</div>
                {threat.controls_correct.map((c,i)=><div key={i} style={{display:"flex",gap:6,fontSize:12.5,color:C.text,padding:"3px 0",lineHeight:1.5}}><span style={{color:C.green,flexShrink:0}}>✓</span>{c}</div>)}
              </Box>
              <Box style={{padding:"10px 12px",background:C.redD,border:`1px solid ${C.red}22`}}>
                <div style={{fontSize:9,fontWeight:700,color:C.red,textTransform:"uppercase",letterSpacing:2,marginBottom:6,fontFamily:C.mono}}>✗ Plausible but Ineffective</div>
                {threat.controls_wrong.map((c,i)=><div key={i} style={{display:"flex",gap:6,fontSize:12.5,color:C.sub,padding:"3px 0",lineHeight:1.5}}><span style={{color:C.red,flexShrink:0}}>✗</span>{c}</div>)}
              </Box>
            </div>
          </Box>
          <Alert type="warn" title="Real-World Precedent">{threat.real_world}</Alert>
        </div>
      )}
      <div style={{display:"flex",justifyContent:"space-between",marginTop:20}}>
        <Btn variant="ghost" onClick={onBack}>◀ BACK</Btn>
        <Btn onClick={onNext}>NEXT: Q4 — VALIDATE ▶</Btn>
      </div>
    </div>
  );
}

// ══ STEP Q4: Validate ═════════════════════════════════════════════════════
function StepQ4({ws,threatAnswers,totalScore,maxScore,onNext,onBack}) {
  const pct=maxScore>0?Math.round(totalScore/maxScore*100):0;
  const grade=pct>=90?"A+":pct>=80?"A":pct>=70?"B":pct>=60?"C":"D";
  const [checks,setChecks]=useState({});
  const checked=Object.values(checks).filter(Boolean).length;
  const allIds=new Set(ws.threats.map(t=>t.id));
  const [detailThreat,setDetailThreat]=useState(null);
  return (
    <div className="fu">
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:12}}>
        <div style={{width:44,height:44,borderRadius:5,background:`${C.green}18`,border:`1.5px solid ${C.green}`,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:C.display,fontSize:18,color:C.green}}>Q4</div>
        <div><div style={{fontFamily:C.display,fontSize:24,color:C.text,letterSpacing:1}}>DID WE DO A GOOD ENOUGH JOB?</div><div style={{fontSize:13,color:C.sub}}>Coverage · Gaps · Next iteration</div></div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:14}}>
        {[["Score",`${totalScore}/${maxScore}`],["Grade",grade],["Accuracy",`${pct}%`],["Threats",threatAnswers.length]].map(([l,v])=>(
          <Box key={l} style={{textAlign:"center",padding:"12px 8px"}}>
            <div style={{fontSize:24,fontWeight:900,color:C.accent,fontFamily:C.display,letterSpacing:1}}>{v}</div>
            <div style={{fontSize:9,color:C.muted,marginTop:2,textTransform:"uppercase",letterSpacing:1.5,fontFamily:C.mono}}>{l}</div>
          </Box>
        ))}
      </div>

      {/* Full mitigation map — final state of the system */}
      <C4Diagram ws={ws} mode="mitigations" revealedThreats={allIds} showMitigations={true}
        onNodeClick={(c,threats)=>threats.length&&setDetailThreat(threats[0])}
        onFlowClick={t=>setDetailThreat(t)}/>
      {detailThreat&&<ThreatDetailPanel threat={detailThreat} showMitigations={true} onClose={()=>setDetailThreat(null)}/>}
      <Alert type="info" style={{marginTop:8,marginBottom:14}} title="Final mitigation map">Green = mitigated. Orange numbers = threat count per component. Click any component to review the threat detail and its controls.</Alert>

      <Box style={{marginBottom:12}}>
        <div style={{fontWeight:700,color:C.text,marginBottom:10,fontFamily:C.mono,fontSize:12,textTransform:"uppercase"}}>Validation Checklist ({checked}/{ws.q4_validation.checklist.length})</div>
        {ws.q4_validation.checklist.map((q,i)=>(
          <div key={i} style={{display:"flex",alignItems:"flex-start",gap:10,padding:"8px 0",borderBottom:i<ws.q4_validation.checklist.length-1?`1px solid ${C.border}`:"none"}}>
            <button onClick={()=>setChecks(c=>({...c,[i]:!c[i]}))} style={{width:22,height:22,borderRadius:4,background:checks[i]?C.greenD:C.raised,border:`1.5px solid ${checks[i]?C.green:C.border}`,cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,marginTop:1}}>
              {checks[i]&&<span style={{color:C.green,fontSize:12}}>✓</span>}
            </button>
            <span style={{fontSize:13.5,color:checks[i]?C.green:C.text,lineHeight:1.6}}>{q}</span>
          </div>
        ))}
      </Box>
      <Alert type="warn" title="Documented Gap">{ws.q4_validation.gap}</Alert>
      <Alert type="info" style={{marginTop:12}} title="Threat models are living documents">Review triggers: any architectural change, new third-party added, significant feature shipped, security incident.</Alert>
      <div style={{display:"flex",justifyContent:"space-between",marginTop:20}}>
        <Btn variant="ghost" onClick={onBack}>◀ BACK</Btn>
        <Btn variant="success" onClick={onNext}>CLAIM CERTIFICATE ▶</Btn>
      </div>
    </div>
  );
}

// ══ CERTIFICATE ════════════════════════════════════════════════════════════
function StepCert({ws,totalScore,maxScore,onRestart}) {
  const pct=maxScore>0?Math.round(totalScore/maxScore*100):0;
  const grade=pct>=90?"A+":pct>=80?"A":pct>=70?"B":pct>=60?"C":"D";
  const today=new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"});
  return (
    <div className="fu">
      <div className="gbg" style={{background:"linear-gradient(135deg,#050f1a 0%,#060415 50%,#050f1a 100%)",border:`1px solid ${C.accent}33`,borderRadius:10,padding:"40px 32px",textAlign:"center",marginBottom:20,boxShadow:`0 0 80px ${C.accent}11`}}>
        <div style={{fontSize:10,fontWeight:700,textTransform:"uppercase",letterSpacing:5,color:C.accent,marginBottom:14,fontFamily:C.mono}}>▸ Certificate of Completion</div>
        <div style={{fontFamily:C.display,fontSize:34,color:C.text,letterSpacing:2,marginBottom:6}}>{ws.name}</div>
        <div style={{fontSize:14,color:C.sub,fontFamily:C.mono,marginBottom:28}}>{ws.subtitle} · {ws.level}</div>
        <div style={{display:"inline-block",background:C.bg,border:`2px solid ${C.amber}`,borderRadius:6,padding:"14px 40px",marginBottom:24}}>
          <div style={{fontSize:52,fontWeight:900,color:C.amber,fontFamily:C.display,letterSpacing:3,lineHeight:1}}>{grade}</div>
          <div style={{fontSize:12,color:C.sub,marginTop:4,fontFamily:C.mono}}>{pct}% · {totalScore}/{maxScore} PTS</div>
        </div>
        <div style={{fontSize:11,color:C.muted,fontFamily:C.mono}}>{today.toUpperCase()}</div>
      </div>
      <div style={{marginBottom:16}}>
        <div style={{fontWeight:700,color:C.text,marginBottom:10,fontFamily:C.mono,fontSize:12,textTransform:"uppercase"}}>Skills Validated</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
          {["Shostack 4-Question Framework end-to-end","Asset classification and assumption documentation","C4-style system decomposition","Trust zone scoring and boundary identification","STRIDE threat derivation without hints","Threat Grammar: precise actionable statements","Attack path simulation — AND/OR gate analysis","Mitigation strategy selection and gap validation"].map((s,i)=>(
            <div key={i} style={{display:"flex",gap:8,padding:"8px 12px",background:C.greenD,border:`1px solid ${C.green}22`,borderRadius:5}}>
              <span style={{color:C.green,flexShrink:0,fontFamily:C.mono}}>✓</span>
              <span style={{fontSize:12.5,color:C.sub,lineHeight:1.6}}>{s}</span>
            </div>
          ))}
        </div>
      </div>
      <div style={{textAlign:"center"}}><Btn variant="ghost" onClick={onRestart}>RESTART WORKSHOP</Btn></div>
    </div>
  );
}

// ══ HOME PAGE ══════════════════════════════════════════════════════════════
function HomePage({onStart,completed}) {
  const [unlock,setUnlock]=useState({});
  const [codes,setCodes]=useState({});
  const workshops=Object.values(WS);
  function tryUnlock(id){const ws=WS[id];if(codes[id]?.toUpperCase()===ws.unlockCode)setUnlock(u=>({...u,[id]:true}));}
  return (
    <div className="fu">
      <div className="gbg" style={{borderRadius:10,border:`1px solid ${C.borderHi}`,padding:"40px 36px",marginBottom:24,position:"relative",overflow:"hidden"}}>
        <div style={{position:"absolute",top:-60,right:-60,width:320,height:320,borderRadius:"50%",background:`radial-gradient(circle,${C.accent}08 0%,transparent 70%)`,pointerEvents:"none"}}/>
        <div style={{fontSize:10,fontWeight:700,letterSpacing:5,color:C.accent,marginBottom:14,fontFamily:C.mono}}>◈ ENTERPRISE SECURITY TRAINING</div>
        <h1 style={{fontFamily:C.display,fontSize:42,color:C.text,letterSpacing:2,margin:"0 0 14px",lineHeight:1.05}}>THREAT MODELING<br/><span style={{color:C.accent}}>MASTERY LAB</span></h1>
        <p style={{fontSize:15,color:C.sub,maxWidth:600,lineHeight:1.85,margin:"0 0 24px"}}>Progressive threat modeling from first principles. You will build understanding step by step — no threat hints until you've earned them.</p>
        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          {[["4-Question Framework",C.accent],["STRIDE from Zero",C.blue],["Blind Zone Labelling",C.purple],["Progressive Discovery",C.amber],["Attack Path Simulation",C.red]].map(([l,col])=><Tag key={l} color={col}>{l}</Tag>)}
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(260px,1fr))",gap:16}}>
        {workshops.map(ws=>{
          const done=completed.has(ws.id);
          const unlocked=ws.access==="FREE"||unlock[ws.id]||done;
          return (
            <div key={ws.id} style={{background:C.card,border:`1px solid ${done?C.green:unlocked?C.borderHi:C.border}`,borderRadius:8,overflow:"hidden",transition:"all .15s",boxShadow:unlocked?`0 0 20px ${ws.levelColor}11`:"none"}}>
              <div style={{padding:"6px 14px",background:`${ws.levelColor}18`,borderBottom:`1px solid ${ws.levelColor}33`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <Tag color={ws.levelColor}>{ws.level}</Tag>
                <span style={{fontSize:11,color:C.muted,fontFamily:C.mono}}>{ws.duration}</span>
              </div>
              <div style={{padding:"16px 18px"}}>
                <div style={{fontWeight:700,color:C.text,fontSize:15,marginBottom:4}}>{ws.name}</div>
                <div style={{fontSize:12,color:C.sub,marginBottom:10,fontFamily:C.mono}}>{ws.subtitle}</div>
                <div style={{fontSize:12.5,color:C.muted,lineHeight:1.6,marginBottom:12}}>{ws.description.slice(0,120)}...</div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:14}}>
                  {ws.compliance.map(c=><Tag key={c} color={C.amber} style={{fontSize:9}}>{c}</Tag>)}
                </div>
                {unlocked?(
                  <Btn onClick={()=>onStart(ws.id)} variant={done?"ghost":"primary"} style={{width:"100%"}}>{done?"REPLAY ↺":"START ▶"}</Btn>
                ):(
                  <div style={{display:"flex",gap:8}}>
                    <input type="text" placeholder="Access code" value={codes[ws.id]||""} onChange={e=>setCodes(c=>({...c,[ws.id]:e.target.value}))}
                      style={{flex:1,padding:"8px 10px",background:C.panel,border:`1px solid ${C.border}`,borderRadius:4,color:C.text,fontSize:12.5,fontFamily:C.mono}}/>
                    <Btn onClick={()=>tryUnlock(ws.id)} variant="ghost" style={{padding:"8px 14px",fontSize:11}}>UNLOCK</Btn>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ══ WORKSHOP VIEW ══════════════════════════════════════════════════════════
function WorkshopView({wsId,onBack,onComplete}) {
  const ws=WS[wsId];
  const [step,setStep]=useState("why");
  const [threatAnswers,setThreatAnswers]=useState([]);
  const totalScore=threatAnswers.reduce((s,a)=>s+a.score,0);
  const maxScore=ws.threats.length*7;
  const go=s=>setStep(s);
  return (
    <div style={{maxWidth:1100,margin:"0 auto",padding:"0 20px 60px"}}>
      <div style={{padding:"14px 0",marginBottom:20,borderBottom:`1px solid ${C.border}`,display:"flex",alignItems:"center",gap:14}}>
        <button onClick={onBack} style={{background:"none",border:`1px solid ${C.border}`,borderRadius:4,padding:"5px 12px",color:C.sub,fontSize:11,fontFamily:C.mono,cursor:"pointer"}}>◀ HOME</button>
        <div style={{flex:1,overflowX:"auto"}}><StepBar current={step}/></div>
      </div>
      {step==="why"     &&<StepWhy onNext={()=>go("s101")}/>}
      {step==="s101"    &&<StepS101 onNext={()=>go("q1")} onBack={()=>go("why")}/>}
      {step==="q1"      &&<StepQ1 ws={ws} onNext={()=>go("q2arch")} onBack={()=>go("s101")}/>}
      {step==="q2arch"  &&<StepQ2Arch ws={ws} onNext={()=>go("q2zones")} onBack={()=>go("q1")}/>}
      {step==="q2zones" &&<StepQ2Zones ws={ws} onNext={()=>go("q2stride")} onBack={()=>go("q2arch")}/>}
      {step==="q2stride"&&<StepQ2Stride ws={ws} answers={threatAnswers} setAnswers={setThreatAnswers} totalScore={totalScore} maxScore={maxScore} onNext={()=>go("q2tree")} onBack={()=>go("q2zones")}/>}
      {step==="q2tree"  &&<StepQ2Tree ws={ws} answers={threatAnswers} onNext={()=>go("q3")} onBack={()=>go("q2stride")}/>}
      {step==="q3"      &&<StepQ3 ws={ws} threatAnswers={threatAnswers} onNext={()=>go("q4")} onBack={()=>go("q2tree")}/>}
      {step==="q4"      &&<StepQ4 ws={ws} threatAnswers={threatAnswers} totalScore={totalScore} maxScore={maxScore} onNext={()=>{onComplete(wsId);go("cert");}} onBack={()=>go("q3")}/>}
      {step==="cert"    &&<StepCert ws={ws} totalScore={totalScore} maxScore={maxScore} onRestart={()=>{setThreatAnswers([]);go("why");}}/>}
    </div>
  );
}

// ══ ROOT APP ════════════════════════════════════════════════════════════════
export default function App() {
  const [view,setView]=useState("home");
  const [wsId,setWsId]=useState(null);
  const [completed,setCompleted]=useState(new Set());
  function startWorkshop(id){setWsId(id);setView("workshop");}
  function completeWorkshop(id){setCompleted(c=>new Set([...c,id]));}
  return (
    <>
      <style>{GCSS}</style>
      <div style={{minHeight:"100vh",background:C.bg}}>
        {view==="home"?(
          <div style={{maxWidth:1100,margin:"0 auto",padding:"32px 20px 60px"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:24,paddingBottom:16,borderBottom:`1px solid ${C.border}`}}>
              <div style={{fontFamily:C.display,fontSize:20,color:C.accent,letterSpacing:2}}>THREAT MODELING MASTERY LAB</div>
              <div style={{display:"flex",gap:8}}>
                {completed.size>0&&<Tag color={C.green}>{completed.size} completed</Tag>}
                <Tag color={C.muted}>v5.0 · Progressive</Tag>
              </div>
            </div>
            <HomePage onStart={startWorkshop} completed={completed}/>
          </div>
        ):(
          <WorkshopView wsId={wsId} onBack={()=>setView("home")} onComplete={completeWorkshop}/>
        )}
      </div>
    </>
  );
}
