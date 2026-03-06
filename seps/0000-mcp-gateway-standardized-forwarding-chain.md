# SEP: MCP Gateway — Standardized Forwarding Chain and Enterprise Governance Infrastructure

**Status:** Draft  
**Type:** Standards Track  
**Created:** 2026-03-05  
**Author:** Ryan Millett  
**Related:** SEP-2357 (`application/mcp+json`), SEP-1961 (Mandatory Security Headers),
SEP-1960 (.well-known Discovery), SEP-1763 (Interceptors), Discussion #804
(Gateway-Based Authorization Model), Discussion #2249 (MCP Enforcement Mode),
Transport Working Group Roadmap (2025-12-19)

---

## Abstract

MCP's rapid adoption in enterprise environments has exposed a challenge distinct
from security in the traditional sense: **governability**. The current architecture
is secure in its components. It is not governable at scale — there is no seam
where an organization can say "governance lives here."

The broader AI governance picture makes the stakes concrete. Industry research
consistently finds that enterprise AI adoption is outpacing governance infrastructure:
over 80% of workers use unapproved AI tools [UpGuard, 2025], one in five organizations
has experienced a breach linked to unsanctioned AI [IBM Cost of Data Breach Report,
2025], and only one in five companies has a mature governance model for autonomous
AI agents [Deloitte State of AI in the Enterprise, 2026]. Regulated industries are
not exempt — they are deploying these tools too, but with a high degree of
organizational angst, deliberately constraining adoption to carefully governed
pockets while the governance gap remains unaddressed [EY, 2025].

MCP does not reduce this problem. It compounds it. Every new MCP server that
enters an organization's ecosystem is a new tool surface that any connected agent
can reach — with no standardized mechanism for an organization to see what is being
called, by whom, or whether it should be permitted. The MCP ecosystem is growing
rapidly, with major vendors publishing official servers and community-built servers
proliferating for nearly every enterprise system. Each additional server multiplies
the unaudited surface area. Without a governance seam in the traffic path, the
risk does not grow linearly with adoption — it grows by orders of magnitude.

For most enterprises, this produces a high-risk compromise: MCP adoption proceeds
in limited, carefully controlled pockets rather than at the scale the technology
enables. For organizations operating under strict regulatory frameworks — FedRAMP,
HIPAA, PCI-DSS — it is a hard blocker to deployment until the control gaps can be
demonstrated as addressed to an external auditor.

This SEP introduces the **MCP Gateway** as a first-class infrastructure role that
provides that seam. It proposes the **minimum set of HTTP transport-layer conventions**
necessary for a conforming, interoperable gateway to exist — not a governance
framework embedded in the protocol, but the small surface area that allows a
governance framework to live outside it. The headers defined here are: `Mcp-Via`
(append-only forwarding chain), `Mcp-Location` (original destination before gateway
rewriting), `Mcp-Correlation-Id` (cross-server audit correlation), `Mcp-Gateway-Agent`
(optional gateway self-identification), and `Mcp-Gateway-Authorization` (recommended
standard location for client-to-gateway credentials).

The proposal operates as an **MCP Extension** — it does not alter the core
JSON-RPC protocol, existing transport semantics, or the client-server capability
model. It defines HTTP transport layer conventions that gateway infrastructure
adopts incrementally; MCP clients and servers that do not participate in gateway
infrastructure are entirely unaffected.

This proposal does not suggest that existing MCP security mechanisms are insufficient for their intended context. It observes that MCP is now being deployed in enterprise contexts that introduce governance requirements the current architecture does not address — contexts where NIST SP 800-53 control families AC, AU, IA, SC, SI, and SR require capabilities that a direct client-to-server deployment structurally cannot provide. The headers defined here are the transport-layer foundation that makes a conforming, interoperable gateway possible. They also establish the prerequisite anchor for the gateway authorization model described in Discussion #804, and align with the Transport Working Group's direction toward stateless, request-carried context.

---

## Motivation

### 1. The Governability Problem

The current MCP architecture is well-suited to a world where a developer
deliberately configures a trusted MCP server, a trusted client connects to it,
and OAuth handles authentication. In that world the security perimeter is the
configuration decision — coherent, well-defined, and sufficient for its context.

Enterprise deployment at scale is a different context. Thousands of users. Dozens
of MCP servers, many chosen by users rather than IT. Multiple AI clients, some
attended, some running autonomously overnight. Regulatory obligations that require
demonstrating control to an external auditor. In this context the current
architecture produces a governance complexity nightmare: policy must be defined,
enforced, and audited independently at every MCP server, with no central
coordination point, no unified audit trail, and no clean ownership structure.
Every new server multiplies the governance surface. The burden scales with every
server, every user, every agent — with no economy of scale.

This is not solved by better OAuth scopes or stricter server-side validation. Those
mechanisms make individual components more secure; they do not make the system
governable. Governability requires a seam — a point in the architecture where
policy is defined once, enforced consistently, and audited centrally. The current
architecture has no such seam.

**Why existing network controls are insufficient:**

Organizations can constrain MCP traffic using firewall rules and DNS blocklists,
TLS inspection appliances, OAuth scope restriction, and endpoint management. Each
of these mechanisms is real. None constitutes a governance framework, individually
or in combination, for two reasons.

First, **granularity**: a firewall operates at hostname level. It can answer
"should any traffic reach this server?" It cannot answer "should this user, acting
through this agent, be permitted to call this specific tool, with these parameters,
at this time of day, given what else this agent has done in this session?" — the
question NIST AC-3 actually requires. To approximate per-tool, per-user,
per-context control at the network layer would require hundreds of rules per server,
rebuilt every time a server, tool, or user group changes, producing no audit trail
that binds invocations to authenticated user identities.

Second, **delegation**: governance frameworks require that controls be owned,
auditable, and delegable — not merely that they exist. A firewall rule maintained
by network operations cannot satisfy an access control requirement for which
information security holds accountability without a formal documented delegation
structure. An MCP gateway creates exactly this structure: security defines policy,
the gateway enforces it, the audit log proves it.

The difference is not technical capability — it is the difference between a control
that is *possible* and one that is *governable*. No regulated organization prevents
email exfiltration by blocking outbound SMTP at the firewall; they deploy DLP
gateways that inspect content, enforce policy, and produce tamper-evident audit
trails. MCP is at exactly this inflection point. §6 below maps the specific NIST
SP 800-53 control families where the absence of a gateway concept produces
concrete, auditable compliance failures.

### 2. MCP Has No Gateway Concept

HTTP has supported proxy and gateway infrastructure since its earliest versions.
Every major HTTP client — browsers, operating system networking stacks, server-side
HTTP libraries — supports proxy configuration as a first-class capability. This
infrastructure is foundational to enterprise network security: forward proxies,
TLS inspection gateways, and DLP appliances all rely on the HTTP proxy model to
govern outbound traffic.

MCP has no equivalent. MCP clients connect directly to MCP servers with no
standardized mechanism for an organization to insert a governance intermediary.
This gap is currently bridged through ad hoc means — local forwarder processes,
network-level traffic redirection — none of which are standardized or
interoperable.

This SEP uses the term **MCP Forwarder** to name an interim deployment pattern that
implementers will need regardless of what this SEP says: a local process that
intercepts outbound MCP traffic and injects the gateway context headers on behalf
of clients that do not yet support gateway configuration natively. Naming the
pattern is useful for consistent description across implementations; this SEP is
not asking the working group to standardize the forwarder as a protocol artifact
— it is an implementation detail that anyone building a gateway needs to solve
for the transition period. The working group's path to making the forwarder unnecessary
runs through two things already on their roadmap: native gateway configuration
support in MCP clients, and canonical MCP traffic identification (such as
`application/mcp+json` per SEP-2357 or equivalent routing headers). When clients
can be pointed at a gateway directly, and when MCP traffic is identifiable at the
infrastructure layer without body inspection, the forwarder's role disappears
entirely.

As MCP matures from developer tooling into regulated enterprise deployments,
organizations subject to data governance requirements — financial services,
healthcare, government — cannot deploy AI agents at scale without a standardized,
auditable governance layer in the MCP traffic path. The absence of a gateway
concept is a critical infrastructure gap.

### 3. The Transport WG Direction Validates Request-Carried Context

The December 2025 Transport Working Group roadmap explicitly moves MCP toward a
stateless transport model — one where sessions and context are carried in requests
rather than maintained as persistent connection state. This direction is directly
consistent with the approach taken in this SEP: routing context and forwarding
chain data are carried as HTTP headers on each request, requiring no persistent
state at the gateway tier.

The roadmap also explicitly identifies infrastructure routing as a first-class
concern, noting the working group is "exploring ways to expose routing-critical
information via standard HTTP headers to allow load balancers and API gateways to
route traffic without parsing JSON bodies." The headers defined in this SEP are a
direct implementation of that direction.

### 4. The Extensions Mechanism Provides a Clean Adoption Path

The November 2025 MCP specification introduced a formal Extensions mechanism —
"components and conventions that operate outside the core specification, providing
a flexible way to build scenario-specific additions that follow MCP conventions
without requiring full protocol integration." The MCP Gateway concept is precisely
the kind of infrastructure-layer addition the Extensions mechanism was designed
to accommodate.

Gateway infrastructure is exactly what the Extensions mechanism was designed for:
it is organizational infrastructure that sits around MCP, not a primitive that
belongs inside it. Placing this proposal in Extensions rather than core keeps
the governance seam where it belongs — outside the protocol, owned by the
organizations that need it, evolving on its own timeline.

### 5. Existing HTTP Headers Are Insufficient for MCP Chain of Custody

HTTP's `Via` header (RFC 7230 §5.7.1) and `Forwarded` header (RFC 7239) were
considered as mechanisms for recording MCP forwarding chains. Both were rejected
for MCP gateway use for the same fundamental reason: they are written by any HTTP
intermediary, not only MCP-aware ones.

In a typical enterprise deployment, MCP traffic passes through multiple generic
HTTP infrastructure components — TLS termination proxies, load balancers, API
management gateways — before reaching any MCP-aware component. Each of these can
write to `Via` or `Forwarded`. The resulting values commingle MCP-aware governance
hops with generic HTTP infrastructure hops, making it impossible to reconstruct a
clean MCP-specific chain of custody without out-of-band knowledge.

A dedicated `Mcp-Via` header, written only by MCP-aware intermediaries, produces
a clean, auditable, MCP-specific chain of custody.

### 6. Enterprise Governance Requirements Cannot Be Met Without a Gateway

As MCP moves into regulated enterprise environments, organizations face a
fundamental compliance problem: the NIST SP 800-53 Rev 5 control families that
govern information systems require capabilities that are architecturally impossible
to satisfy in a direct client-to-server MCP deployment.

The following control families identify specific gaps that an MCP gateway directly
addresses. In each case, the gap is not a configuration problem or an implementation
shortcoming — it is a structural absence in the protocol that no amount of
client-side or server-side hardening can resolve without an intermediary.

**AC — Access Control (AC-2, AC-3, AC-6)**
NIST requires that information systems enforce approved authorizations for logical
access, apply least-privilege principles, and control access based on the identity
of the user — not merely the identity of the application. Even where individual
MCP servers perform user-aware access control, each does so independently against
its own authorization model. There is no mechanism to enforce a consistent
least-privilege policy across the full set of MCP servers an agent can reach, or
to express cross-server constraints such as "this user may read from the file
server or send email, but not both in the same session." An MCP gateway is the
only architectural position from which user-aware, cross-server access control
policy can be enforced uniformly without requiring each server to independently
implement organization-wide policy.

**AU — Audit and Accountability (AU-2, AU-3, AU-9, AU-12)**
NIST requires that information systems generate audit records sufficient to
establish what events occurred, who caused them, and when — and protect those
records from unauthorized modification. In a direct MCP deployment, audit records
are generated independently by each MCP server, if at all. There is no mechanism
to produce a unified, tamper-evident audit trail that binds tool invocations to
authenticated user identities across the full scope of an agent's activity. An
unattended agent calling ten different MCP servers produces ten independent,
unlinked log fragments — insufficient for NIST AU-3 (content of audit records)
or AU-9 (protection of audit information). An MCP gateway is the only point from
which a unified, identity-bound audit trail can be produced covering all MCP
activity regardless of which servers are involved.

**IA — Identification and Authentication (IA-2, IA-4, IA-8)**
NIST requires that information systems uniquely identify and authenticate users —
including organizational users, non-organizational users, and non-human entities
such as automated processes. OAuth flows vary in whether they carry user identity
through to the MCP server, and there is no standardized mechanism at the MCP layer
to consistently represent the human principal on whose behalf an agent is acting
across heterogeneous MCP deployments. An MCP gateway is the only position from
which consistent IA-2 and IA-8 compliance can be achieved regardless of how
individual servers handle OAuth claims.

**SC — System and Communications Protection (SC-7, SC-8)**
NIST requires that organizations monitor and control communications at external
boundaries and implement subnetwork controls for components that are externally
accessible. MCP clients connecting directly to external MCP servers — over the
public internet, to third-party operators — constitute external boundary crossings
that NIST SC-7 requires to be monitored and controlled. Without a gateway, there
is no boundary control point. The MCP client connects directly to any MCP server
its configuration references, with no organizational visibility or control over
what crosses the boundary or in which direction.

**SI — System and Information Integrity (SI-4, SI-7)**
NIST requires that organizations monitor information systems to detect attacks and
indicators of compromise, and protect the integrity of software and information.
An AI agent calling MCP tools at machine speed, across multiple systems, can
exfiltrate data through sequences of individually-innocuous tool calls — a pattern
that no single MCP server can detect because no single server sees the full
sequence. Only a gateway that observes all MCP traffic from a given agent can
detect cross-server anomalous patterns. SI-4 (information system monitoring) is
structurally unachievable for MCP without a central observation point.

**SR — Supply Chain Risk Management (SR-6)**
NIST requires that organizations assess and manage the risks associated with
third-party components in the supply chain. MCP servers are third-party software
that agents connect to and execute tools from. Without a gateway maintaining an
approved server registry and validating server identity before permitting
connections, organizations cannot satisfy SR-6 for their MCP supply chain. An
agent configured to connect to any MCP server URL — a configuration that is the
current default — is equivalent to allowing unrestricted third-party code execution
with no supply chain controls.

The controls above are not aspirational — they are required baselines for
organizations operating under FedRAMP, HIPAA, PCI-DSS, SOC 2 Type II, and
comparable frameworks. The absence of an MCP gateway concept does not mean these
organizations can avoid the controls; it means they cannot deploy MCP at all until
the control gaps are addressed. A standardized MCP gateway, defined at the protocol
level, is what enables regulated industries to adopt MCP.

### 7. This Proposal Is the Minimum Necessary — Not a Governance Framework

The community has proposed approaches that address the governance problem by
extending the MCP protocol itself. This SEP takes a different position: governance
is a concern that should live *around* MCP, not inside it. The protocol's job is
to define how AI clients connect to tools and data. Policy enforcement, audit
storage, anomaly detection, and compliance reporting are organizational concerns
that belong in infrastructure that observes and governs MCP traffic — infrastructure
that can evolve independently of the protocol it governs.

HTTP does not have firewall rules built into it. TCP/IP does not have DLP policies.
Those concerns are handled by infrastructure in the traffic path. MCP should be no
different.

This SEP therefore proposes only what is strictly necessary to create the seam where
governance infrastructure can attach — not the governance infrastructure itself.
Each header is evaluated against a single question: *is this the minimum necessary
to enable external governance, or is this governance itself?* Headers that are
governance themselves are out of scope for this SEP and belong in implementation.
Headers that are minimum necessary for governance to be possible are in scope.

**Discussion #804 — Gateway-Based Authorization Model (June 2025):** This community
proposal describes a gateway architecture in which the gateway validates the client's
OAuth token, evaluates dynamic policy, and mints a short-lived signed assertion JWT
to forward to the backend MCP server. The proposal is framed as an infrastructure
overlay requiring no protocol changes.

The headers defined in this SEP are the transport-layer foundation that Discussion
#804's authorization model requires but does not define. Specifically, `Mcp-Via`
enables an MCP server to verify that a request arrived through a known, trusted
gateway before accepting an assertion JWT — without `Mcp-Via`, an MCP server has
no transport-layer signal that a request passed through gateway infrastructure at
all. This SEP and Discussion #804 are complementary and non-overlapping: this SEP
defines the forwarding chain and context headers; a future SEP can define the
assertion JWT format and gateway trust model that builds on them.

**Discussion #2249 — MCP Enforcement Mode (February 2026):** This proposal observes
that gateway governance is only meaningful if AI agents cannot bypass the gateway
entirely — for example, by shelling out to a CLI or making direct HTTP calls outside
the MCP path. It proposes a host-declared capability flag signaling that the
environment enforces MCP as the only permitted path for side-effectful actions.
Discussion #2249 makes this SEP's argument from the other direction: the gateway
defines the governance seam; enforcement mode is the mechanism that makes the seam
meaningful. The two proposals are sequential, not competing.

**SEP-1763 — Interceptors (November 2025):** This proposal defines a protocol-layer
interceptor framework — validation, mutation, and observability hooks built into
MCP itself as a new JSON-RPC resource type. It is a substantive contribution, but
it solves the governance problem by extending the protocol inward. Governance
concerns are embedded in the core protocol, server adoption is voluntary, and the
interceptor surface area grows with every new MCP event type.

This SEP takes the opposite approach. The transport-layer headers defined here add
minimal surface area to the protocol. All governance logic — policy evaluation,
audit storage, anomaly detection — lives entirely outside MCP and evolves
independently. An MCP server that does not cooperate with governance infrastructure
is still subject to gateway enforcement because traffic must pass through the gateway
regardless. The two approaches are not mutually exclusive: an MCP server could
simultaneously use `Mcp-Via` for transport-layer chain of custody and SEP-1763
interceptors for protocol-layer validation. But for organizations that need
governance to be mandatory rather than cooperative, the transport-layer gateway is
the structurally sound foundation.

---

## Specification

### 3.1 Definitions

**MCP Gateway:** An MCP-aware HTTP intermediary that receives forwarded MCP
traffic, applies policy, and forwards permitted traffic upstream. A gateway
actively evaluates policy and appends to the `Mcp-Via` forwarding chain.

**MCP Forwarder:** A term used in this SEP to describe an interim deployment pattern — a
transparent traffic redirector that intercepts outbound MCP traffic from an MCP
client and forwards it to a gateway or MCP server. A forwarder does not evaluate
policy — it injects context headers and redirects traffic. This SEP names the
pattern for consistent use across implementations; it does not ask the working
group to standardize the forwarder as a protocol artifact. The need for this
pattern dissolves when MCP clients natively support gateway configuration and
when MCP traffic is canonically identifiable at the infrastructure layer.

**Origin:** The first MCP-aware hop — typically a forwarder or, in future native
implementations, the MCP client itself — that establishes the immutable context
headers in the request.

**Forwarding Chain:** The ordered sequence of MCP-aware intermediaries recorded
in the `Mcp-Via` header fields.

### 3.2 Header Overview

This SEP defines five headers, organized by where in the forwarding chain they
originate and who is responsible for them.

**Client → Gateway (set by the client or forwarder at the origin, before the first gateway):**

| Header | Requirement | Purpose |
|--------|-------------|---------|
| `Mcp-Gateway-Authorization` | RECOMMENDED | Client authenticates to the gateway |
| `Mcp-Location` | REQUIRED | Original intended destination before gateway rewriting |
| `Mcp-Correlation-Id` | RECOMMENDED | Cross-server audit correlation scope |

**Pass-Through (client-originated, preserved unchanged end-to-end):**

| Header | Requirement | Notes |
|--------|-------------|-------|
| `User-Agent` | Preserve | Client application identity; forwarders and gateways MUST NOT substitute their own value |
| `Authorization` | Preserve | Principal security context; MAY be substituted by gateway with scoped credentials when required by the deployment |
| `Mcp-Correlation-Id` | Preserve | Set by client, forwarded to MCP server unchanged; SHOULD be an opaque unpredictable value (UUID) with no embedded semantics |

**Gateway → MCP Server (set or appended by the gateway on the outbound leg):**

| Header | Requirement | Purpose |
|--------|-------------|---------|
| `Mcp-Via` | REQUIRED | Gateway appends its entry to the forwarding chain |
| `Mcp-Gateway-Agent` | OPTIONAL | Gateway self-identification for metrics and ecosystem differentiation |

### 3.3 Message Boundaries and Header Responsibilities

This section describes the message boundaries for two deployment topologies: the
target future state, in which MCP clients natively support gateway configuration,
and the interim forwarder pattern, which enables deployment today without client
changes.

#### Future State — Native Client Gateway Support

This is the target architecture this SEP proposes. The MCP client is configured
with a gateway address and injects the Client → Gateway headers directly. No
forwarder process is required.

```
                    +-------------------------------------+
                    |         ENTERPRISE BOUNDARY         |
                    |                                     |
  MCP Client        |      Gateway Server                 |   MCP Server
      |             |           |                         |       |
      |-------------+---------->|                         |       |
      |  [A]        |           |-------------------------|------>|
      |             |           |  [B]                    |       |
      |             |           |<------------------------|-------|
      |<------------+-----------|  [C]                    |       |
      |             |           |                         |       |
                    +-------------------------------------+

  [A] Client -> Gateway         [C] MCP Server -> Client (response path)
  [B] Gateway -> MCP Server
```

##### Boundary [A] — MCP Client to Gateway

The MCP client sends the request directly to the configured gateway address,
injecting the Client → Gateway headers:

```http
Mcp-Location: {original-destination-url}
Mcp-Correlation-Id: {opaque-uuid}
Mcp-Gateway-Authorization: Bearer {token}      (if gateway enrollment required)
```

All standard MCP headers — `Authorization`, `User-Agent`, `Mcp-Protocol-Version`,
`Mcp-Session-Id` — are included as normal.

##### Boundary [B] — Gateway to MCP Server (outbound)

The gateway evaluates policy, appends its `Mcp-Via` entry, and forwards to the
upstream MCP server. All Client → Gateway context headers are preserved unchanged.

```http
Mcp-Via: type=gateway; host={gateway-host}; mcpgw=1.0     <- appended by gateway
Mcp-Gateway-Agent: AcmeMcpGateway/2.1 (governance; dlp)   <- optional
Mcp-Location: {original-destination-url}                   <- preserved, unchanged
Mcp-Correlation-Id: {opaque-uuid}                          <- preserved, unchanged
User-Agent: claude-desktop/1.4.2                           <- preserved, unchanged
Authorization: Bearer {gateway-scoped-token}                <- MAY be replaced
```

`Mcp-Gateway-Authorization` is consumed by the gateway and MUST NOT be forwarded
to the upstream MCP server.

##### Boundary [C] — Response Path (MCP Server back to Client)

MCP server responses traverse the chain in reverse. The gateway on the return path:

- MUST NOT strip or modify `Mcp-Via` fields from the request path
- SHOULD propagate response headers from the MCP server unchanged
- MAY append a `Mcp-Via` entry to the response to record the return path

Response `Mcp-Via` propagation is OPTIONAL in this version of the specification.
A future revision may make it RECOMMENDED to enable clients to verify the return
path was governed equivalently to the request path.

---

#### Interim Pattern — Forwarder Deployment

This topology describes how gateway infrastructure can be deployed today, before
MCP clients support native gateway configuration. A local forwarder process
intercepts outbound MCP traffic and injects the Client → Gateway headers on the
client's behalf. The forwarder introduces two additional boundaries compared to
the future state. This pattern is not a working group concern — it is an
implementation detail for organizations that need to deploy governance
infrastructure before native client support arrives.

```
                    +-------------------------------------+
                    |         ENTERPRISE BOUNDARY         |
                    |                                     |
  MCP Client        |  Forwarder      Gateway Server      |   MCP Server
      |             |      |               |              |       |
      |-------------+----->|               |              |       |
      |  [A]        |      |-------------->|              |       |
      |             |      |  [B]          |--------------|------>|
      |             |      |               |  [C]         |       |
      |             |      |               |<-------------|-------|
      |             |      |<--------------|  [D]         |       |
      |<------------+------|               |              |       |
      |             |      |               |              |       |
                    +-------------------------------------+

  [A] Client -> Forwarder      [C] Gateway -> MCP Server (outbound)
  [B] Forwarder -> Gateway     [D] MCP Server -> Client (response path)
```

##### Boundary [A] — MCP Client to Forwarder

The MCP client issues a standard MCP request addressed to the target MCP server.
No gateway headers are present. The forwarder intercepts this request before it
leaves the enterprise boundary.

##### Boundary [B] — Forwarder to Gateway Server

The forwarder injects the Client → Gateway headers and rewrites the destination
to the gateway address. This is where the context headers are established,
performing the role that a gateway-aware client would perform natively.

```http
Mcp-Via: type=forwarder; host={forwarder-host}; mcpgw=1.0
Mcp-Location: {original-destination-url}
Mcp-Correlation-Id: {opaque-uuid}              (if not already set by client)
Mcp-Gateway-Authorization: Bearer {token}      (if gateway enrollment required)
```

All existing headers from the client request — including `Authorization`,
`User-Agent`, `Mcp-Protocol-Version`, `Mcp-Session-Id` — are preserved unchanged.
If the client has already set `Mcp-Correlation-Id`, the forwarder MUST preserve
the existing value rather than generating a new one.

##### Boundary [C] — Gateway to MCP Server (outbound)

Identical to Boundary [B] in the future state topology, with the addition that
the forwarder's `Mcp-Via` entry is preserved in the chain:

```http
Mcp-Via: type=forwarder; host={forwarder-host}; mcpgw=1.0   <- preserved from [B]
Mcp-Via: type=gateway;   host={gateway-host}; mcpgw=1.0     <- appended by gateway
Mcp-Gateway-Agent: AcmeMcpGateway/2.1 (governance; dlp)     <- optional
Mcp-Location: {original-destination-url}                     <- preserved, unchanged
Mcp-Correlation-Id: {opaque-uuid}                            <- preserved, unchanged
User-Agent: claude-desktop/1.4.2                             <- preserved, unchanged
Authorization: Bearer {gateway-scoped-token}                  <- MAY be replaced
```

##### Boundary [D] — Response Path (MCP Server back to Client)

Identical to Boundary [C] in the future state topology. The forwarder on the
return path MUST NOT strip or modify any `Mcp-Via` fields.

---

**What the gateway does NOT add on the outbound leg:** In both topologies, beyond
appending its own `Mcp-Via` entry, optionally appending `Mcp-Gateway-Agent`, and
optionally substituting credentials, the gateway adds no additional headers. The
context established at the origin is sufficient. The gateway's policy decision
(permit/deny) is expressed by whether the request is forwarded at all — not by
additional headers.

### 3.4 The `Mcp-Via` Header

#### 3.4.1 Syntax

```
Mcp-Via       = mcp-via-entry
mcp-via-entry = type-param ";" host-param ";" version-param *(";" extension-param)
type-param    = "type=" ("forwarder" / "gateway" / token)
host-param    = "host=" host-identifier
version-param = "mcpgw=" 1*DIGIT "." 1*DIGIT
extension-param = token "=" (token / quoted-string)
host-identifier = uri-host / quoted-string
```

Each `Mcp-Via` header field represents one MCP-aware hop. Multiple hops are
represented as multiple `Mcp-Via` header fields in order of traversal.

#### 3.4.2 Type Values

| Value | Description |
|-------|-------------|
| `forwarder` | Transparent redirector — no policy evaluation |
| `gateway` | Policy-enforcing MCP gateway |

Additional type values MAY be defined by future SEPs.

#### 3.4.3 Append Semantics

`Mcp-Via` is append-only. Each MCP-aware intermediary MUST add one `Mcp-Via` field
identifying itself. Intermediaries MUST NOT modify or remove existing `Mcp-Via`
fields. Generic HTTP intermediaries that are not MCP-aware MUST NOT add `Mcp-Via`
fields.

### 3.5 The `Mcp-Location` Header

The original destination MCP server URL before any gateway rewriting.

```http
Mcp-Location: https://gmail.mcp.claude.com
```

Allows the final MCP server and audit systems to determine the client's intended
destination independent of any rewriting performed by gateways in the chain.
`Mcp-Location` carries a full URL — scheme, host, and path — consistent with the
established HTTP convention of using `Location` for URL-valued fields.

**Set by:** Origin (forwarder or native client). **Mutability:** Immutable downstream.

### 3.6 The `Mcp-Correlation-Id` Header

An opaque identifier that groups related MCP tool calls into a logical operation
for audit and correlation purposes.

```http
Mcp-Correlation-Id: 7f3a9c2e-4b1d-4e8f-a6c0-2d5e8f1a3b9c
```

The value SHOULD be an unpredictable, opaque identifier (UUID or equivalent) with
no embedded semantics. Implementors MUST NOT encode user identities, session
details, or sequential counters into the correlation ID, as this value is forwarded
to upstream MCP servers and may be logged by third-party operators.

The scope of a correlation ID is a client concern. Clients may assign a single
correlation ID per tool call, per conversational turn, per session, or per
long-running workflow — whichever granularity serves their audit requirements.
Gateways treat the value as opaque and route on it only for rate-limiting or
anomaly detection purposes; they do not interpret its scope.

`Mcp-Correlation-Id` is forwarded to the upstream MCP server unchanged. This
allows MCP server logs to be correlated with gateway audit records using the same
identifier, producing an end-to-end audit trail without requiring out-of-band
log correlation.

**Set by:** Client or forwarder (if not already present). **Mutability:** Immutable
downstream. **Forwarding:** Pass-through to MCP server.

### 3.7 The `Mcp-Gateway-Agent` Header

An optional header through which a gateway advertises its identity, version, and
capability profile to downstream MCP servers.

```http
Mcp-Gateway-Agent: AcmeMcpGateway/2.1 (governance; dlp; audit-certified)
```

Format follows the `User-Agent` / `Server` convention: `{product}/{version}` with
an optional parenthetical containing space-separated capability tokens. In a
multi-hop chain, each gateway MUST append its own `Mcp-Gateway-Agent` value — the
resulting ordered set of values corresponds to the ordered set of `Mcp-Via` entries
and identifies both that a gateway was present and what kind of gateway it was.

Capability tokens are informational only and carry no inherent trust. MCP servers
MUST NOT grant elevated permissions based solely on claimed capability tokens.
No registry of capability tokens is defined in this version of the specification;
implementations define their own. A future SEP may standardize common tokens as
the ecosystem converges.

**Set by:** Each gateway on the outbound leg. **Mutability:** Append-only.
**Authority:** Informational only — MUST NOT be used as a trust signal.

### 3.8 The `Mcp-Gateway-Authorization` Header

A recommended standard location for client-to-gateway credentials, separate from
the `Authorization` header the client presents to the upstream MCP server.

```http
Mcp-Gateway-Authorization: Bearer {gateway-enrollment-token}
```

Gateway infrastructure will inevitably require clients to authenticate before
routing their traffic — to enforce enrollment, apply per-client policy, or satisfy
audit requirements. Without a standardized header, each gateway vendor will invent
a proprietary mechanism, fragmenting the ecosystem and increasing client
implementation complexity.

This header follows the same convention as HTTP's `Authorization` header: it
defines a standard *location* for credentials without prescribing the credential
format, OAuth flow, or key exchange mechanism. Those decisions are implementation-
specific and outside the scope of this SEP and the MCP protocol.

`Mcp-Gateway-Authorization` is consumed by the gateway and MUST NOT be forwarded
to the upstream MCP server.

**Set by:** Client or forwarder. **Forwarding:** Consumed at first gateway, not forwarded upstream.

### 3.9 Complete Governed Request Examples

#### Future State — Native Client Gateway Support

A request from Claude Desktop configured to use a corporate gateway directly,
destined for the Gmail MCP server. The client injects the Client → Gateway
headers natively — no forwarder involved.

**Sent by MCP Client to Gateway Server:**

```http
POST /mcp HTTP/1.1
Host: gw.corp.example.com
Content-Type: application/mcp+json
Authorization: Bearer {user-token}
User-Agent: claude-desktop/1.4.2
Mcp-Protocol-Version: 2025-11-25
Mcp-Session-Id: {session-uuid}
Mcp-Location: https://gmail.mcp.claude.com
Mcp-Correlation-Id: 7f3a9c2e-4b1d-4e8f-a6c0-2d5e8f1a3b9c
Mcp-Gateway-Authorization: Bearer {enrollment-token}

{ ...json-rpc tool call body... }
```

**Forwarded by Gateway Server to MCP Server:**

```http
POST /mcp HTTP/1.1
Host: gmail.mcp.claude.com
Content-Type: application/mcp+json
Authorization: Bearer {gateway-scoped-token}
User-Agent: claude-desktop/1.4.2
Mcp-Protocol-Version: 2025-11-25
Mcp-Session-Id: {session-uuid}
Mcp-Via: type=gateway; host=gw.corp.example.com; mcpgw=1.0
Mcp-Gateway-Agent: AcmeMcpGateway/2.1 (governance; dlp)
Mcp-Location: https://gmail.mcp.claude.com
Mcp-Correlation-Id: 7f3a9c2e-4b1d-4e8f-a6c0-2d5e8f1a3b9c

{ ...json-rpc tool call body... }
```

#### Interim Pattern — Forwarder Deployment

The same request, but using a desktop forwarder to inject the Client → Gateway
headers on behalf of a client that does not yet support native gateway configuration.

**Received by Gateway Server (after forwarder injection):**

```http
POST /mcp HTTP/1.1
Host: gw.corp.example.com
Content-Type: application/mcp+json
Authorization: Bearer {user-token}
User-Agent: claude-desktop/1.4.2
Mcp-Protocol-Version: 2025-11-25
Mcp-Session-Id: {session-uuid}
Mcp-Via: type=forwarder; host=desktop-fw.corp.example.com; mcpgw=1.0
Mcp-Location: https://gmail.mcp.claude.com
Mcp-Correlation-Id: 7f3a9c2e-4b1d-4e8f-a6c0-2d5e8f1a3b9c
Mcp-Gateway-Authorization: Bearer {enrollment-token}

{ ...json-rpc tool call body... }
```

**Forwarded by Gateway Server to MCP Server:**

```http
POST /mcp HTTP/1.1
Host: gmail.mcp.claude.com
Content-Type: application/mcp+json
Authorization: Bearer {gateway-scoped-token}
User-Agent: claude-desktop/1.4.2
Mcp-Protocol-Version: 2025-11-25
Mcp-Session-Id: {session-uuid}
Mcp-Via: type=forwarder; host=desktop-fw.corp.example.com; mcpgw=1.0
Mcp-Via: type=gateway;   host=gw.corp.example.com; mcpgw=1.0
Mcp-Gateway-Agent: AcmeMcpGateway/2.1 (governance; dlp)
Mcp-Location: https://gmail.mcp.claude.com
Mcp-Correlation-Id: 7f3a9c2e-4b1d-4e8f-a6c0-2d5e8f1a3b9c

{ ...json-rpc tool call body... }
```

In both topologies, `Mcp-Gateway-Authorization` is consumed by the gateway and
absent on the outbound leg. `Authorization` carries a gateway-scoped token. All
other context headers are preserved unchanged from the origin. The MCP server can
correlate its own execution logs against gateway audit records using
`Mcp-Correlation-Id`. The only observable difference between the two examples at
the MCP server is the presence of the forwarder's `Mcp-Via` entry in the interim
pattern — the upstream server receives complete governance context either way.

### 3.10 Loop Detection

Gateways MUST check whether their own `host` identifier already appears in any
existing `Mcp-Via` field before forwarding. If detected, the gateway MUST NOT
forward the request and MUST return an error response:

```http
HTTP/1.1 508 Loop Detected
Content-Type: application/mcp+json

{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "MCP gateway forwarding loop detected"
  },
  "id": null
}
```

### 3.11 Forwarder Responsibilities

The responsibilities listed here are not unique to the forwarder — they are
exactly what a gateway-aware MCP client will perform natively when native gateway
configuration support arrives. The forwarder exists to perform these behaviors on
the client's behalf during the transition period. This section therefore serves
a dual purpose: it specifies the forwarder's behavior today, and it specifies
what MCP clients MUST implement when adopting native gateway support.

An MCP Forwarder MUST, on every request it forwards:

1. Add one `Mcp-Via` field: `type=forwarder; host={own-host}; mcpgw=1.0`
2. Set `Mcp-Location` to the original destination URL if not already present
3. Set `Mcp-Correlation-Id` to a new opaque UUID if not already present in the request
4. Preserve `User-Agent` from the client request unchanged — MUST NOT substitute the forwarder's own value
5. Preserve `Authorization` and all other client headers unchanged
6. Rewrite the request destination to the configured gateway address
7. Inject `Mcp-Gateway-Authorization` from the provisioned enrollment credential if
   gateway enrollment is required; the value is provisioned out-of-band and is not
   supplied by the client at request time
8. MUST NOT evaluate policy

### 3.12 Gateway Server Responsibilities

An MCP Gateway MUST, on every request it processes:

1. Perform loop detection per §3.10 before any further processing
2. Validate `Mcp-Gateway-Authorization` if gateway enrollment is required
3. Read available context (`Mcp-Location`, `Mcp-Correlation-Id`, `User-Agent`,
   `Authorization`) for policy evaluation
4. Apply policy — the permit/deny decision is expressed by whether the request is forwarded
5. If forwarding: append one `Mcp-Via` field: `type=gateway; host={own-host}; mcpgw=1.0`
6. If forwarding: optionally append `Mcp-Gateway-Agent` identifying this gateway
7. If forwarding: strip `Mcp-Gateway-Authorization` — MUST NOT forward to upstream
8. If forwarding: preserve `Mcp-Location`, `Mcp-Correlation-Id`, and `User-Agent` unchanged
9. If forwarding: MAY substitute the `Authorization` header with gateway-scoped credentials
   while preserving all other `Mcp-*` context headers unchanged

### 3.13 MCP Server Behavior

MCP servers receiving requests with gateway headers:

- SHOULD log `Mcp-Via`, `Mcp-Location`, `Mcp-Correlation-Id`, `Mcp-Gateway-Agent`,
  and `User-Agent` for audit purposes, enabling end-to-end correlation with gateway
  audit records via `Mcp-Correlation-Id`
- MAY enforce policy based on the `Mcp-Via` chain — for example, requiring at
  least one `type=gateway` entry as a precondition for accepting assertion JWTs
  (per the pattern described in Discussion #804)
- MUST NOT reject conforming requests solely because gateway headers are present
- MUST NOT reject conforming requests solely because gateway headers are absent,
  during the transition period defined in §3.14

### 3.14 Transition and Backward Compatibility

This proposal is designed for incremental adoption. The MCP Forwarder exists
solely to bridge the gap between today's clients and the native gateway support
that is the intended end state. As native support becomes available in MCP clients,
the forwarder role becomes unnecessary. The working group is not asked to
standardize the forwarder — the working group's contributions that eliminate the
need for it are native client gateway configuration and canonical MCP traffic
identification. Those are already on the roadmap independently of this SEP.

**Phase 1 — Extension (immediate):** Implementers deploying gateway infrastructure
MAY use a local forwarder process to inject the headers defined in this SEP on
behalf of MCP clients that do not yet have native gateway support. MCP servers and
clients MUST accept and ignore unknown `Mcp-*` headers per existing MCP conventions.
No existing implementation is broken.

**Phase 2 — Recommended (next spec revision):** The specification SHOULD declare
`Mcp-Via` injection as RECOMMENDED for MCP gateway infrastructure. MCP clients
SHOULD adopt native gateway configuration support, allowing users to specify a
gateway address directly. At this point the forwarder becomes an optional
convenience for legacy clients, not a required component.

**Phase 3 — Required for gateway implementations (future spec revision):**
Conforming MCP gateway implementations MUST implement this SEP. MCP clients with
native gateway support MUST inject the Client → Gateway headers. The forwarder
is fully legacy at this phase — a compatibility shim for clients that have not
yet adopted native support, not part of the standard deployment topology.

At no point does adoption of this SEP require changes to existing MCP client or
server implementations that do not participate in gateway infrastructure.

### 3.15 Relationship to Other Proposed Headers

The complete header set for a fully governed MCP request as it arrives at the
upstream MCP server:

```http
Content-Type: application/mcp+json               <- SEP-2357: traffic identification
Mcp-Protocol-Version: 2025-11-25                 <- existing: protocol version
Mcp-Session-Id: {uuid}                           <- existing: session tracking
Mcp-Method: tools/call                           <- WG routing proposal: operation type
Mcp-Tool-Name: send_email                        <- WG routing proposal: tool identity
Mcp-Via: type=forwarder; host=...; mcpgw=1.0    <- this SEP: forwarding chain (forwarder)
Mcp-Via: type=gateway;   host=...; mcpgw=1.0    <- this SEP: forwarding chain (gateway)
Mcp-Gateway-Agent: AcmeMcpGateway/2.1           <- this SEP: gateway identity
Mcp-Location: https://gmail.mcp.claude.com       <- this SEP: original destination
Mcp-Correlation-Id: {uuid}                       <- this SEP: cross-server audit correlation
User-Agent: claude-desktop/1.4.2                 <- existing: client application identity
Authorization: Bearer {token}                    <- existing: authentication
```

---

## Gateway Trust — A Foundation for Future Work

This SEP deliberately stops short of defining how MCP servers should verify that
a claimed `Mcp-Via` chain is authentic — i.e., that the gateways listed actually
processed the request and were not spoofed by a client injecting fabricated headers.

This is an intentional design decision. The `Mcp-Via` forwarding chain establishes
the *transport-layer convention* and *audit record* for gateway infrastructure. It
is the prerequisite for gateway trust — but trust verification is a distinct
problem that warrants its own SEP and community discussion.

The natural next step, consistent with Discussion #804, is a gateway attestation
mechanism: a cryptographically signed assertion that an MCP server can verify came
from a legitimate, known gateway. The `Mcp-Via` chain is what makes such an
assertion meaningful — an MCP server can check both that the request claims to
have passed through a gateway (`Mcp-Via`) and that the claim is cryptographically
verifiable (attestation JWT). Without the forwarding chain header, attestation has
no transport-layer anchor.

This SEP sets the stage. Gateway attestation is deferred to a future SEP.

---

## Security Considerations

### Header Spoofing

The headers defined in this SEP carry no inherent authority. Any HTTP client can
set these headers to arbitrary values. Infrastructure MUST NOT grant elevated trust
or bypass authentication based solely on the presence of these headers.

The chain of trust is established by organizational configuration and — in the
future — cryptographic attestation, not by the headers themselves. Organizations
deploying MCP gateway infrastructure SHOULD configure upstream HTTP infrastructure
to strip client-originated `Mcp-Via` fields at the enterprise boundary, establishing
a clean chain of custody from a known, trusted origin point.

### `Mcp-Via` Injection by Non-MCP Infrastructure

Generic HTTP intermediaries MUST NOT write `Mcp-Via` fields. The value of the
MCP-specific header is precisely that it records only MCP-aware hops. Organizations
SHOULD audit their infrastructure configuration to confirm that non-MCP components
are not injecting `Mcp-Via` values.

### `Mcp-Correlation-Id` Privacy

`Mcp-Correlation-Id` is forwarded to upstream MCP servers, including third-party
operators. Implementations MUST use opaque, unpredictable values with no embedded
semantics. Correlation IDs that encode user identities, sequential counters, or
internal system identifiers create a privacy risk when forwarded to external
parties. A UUID v4 is the recommended format.

### Credential Substitution at Gateways

Gateways that substitute the `Authorization` header MUST ensure that substituted
credentials are scoped to the permissions of the original principal as established
by the incoming bearer token or organizational identity context. Gateways MUST NOT
substitute credentials granting permissions exceeding those of the original principal.

### `Mcp-Gateway-Authorization` Isolation

`Mcp-Gateway-Authorization` MUST be stripped by the gateway before forwarding.
Forwarding this header to an upstream MCP server would expose client-to-gateway
credentials to a third party. Gateways that receive a request without this header
when enrollment is required SHOULD return `HTTP 401 Unauthorized` rather than
forwarding with degraded trust context.

---

## Alternatives Considered

### A. Reuse HTTP `Via` or `Forwarded` Headers

Rejected. Generic HTTP intermediaries write to these headers; they cannot
represent a clean MCP-specific chain of custody. See §5.

### B. Single-Value `Mcp-Gateway` Header

Rejected. Cannot represent multi-hop chains — a second gateway would overwrite
the first, destroying the chain-of-custody record.

### C. Encode Forwarding Chain in the JSON-RPC Body

Rejected. Requires body parsing at every infrastructure layer, defeats the
infrastructure-routing goals shared with SEP-2357, and modifies the JSON-RPC
payload in ways that are not transparent to MCP servers.

### D. Extend Existing `Mcp-Session-Id` Semantics

Rejected. `Mcp-Session-Id` identifies a session, not a forwarding chain or
correlation scope. These are distinct concepts that should not be conflated — a
single session may traverse multiple gateways, a single gateway may serve many
sessions, and correlation scope may span multiple sessions in long-running workflows.

### E. Use `Mcp-Principal-Id` / `Mcp-Agent-Id` / `Mcp-Client-Id` Headers

Considered and rejected in favor of relying on existing HTTP conventions.
`User-Agent` is the established standard for identifying the originating client
application; introducing `Mcp-Client-Id` would duplicate it without justification.
`Authorization` already carries the principal's security context via bearer token;
a duplicate `Mcp-Principal-Id` creates accuracy and maintenance concerns. A
dedicated `Mcp-Agent-Id` conflates agent identity with audit correlation —
`Mcp-Correlation-Id` is the correct primitive, and its scope is a client concern
that the gateway need not interpret.

---

## Reference Implementation

The authors commit to providing an open source reference implementation
demonstrating the header conventions defined in this SEP prior to formal review.

The implementation will include a desktop forwarder and gateway server. The
forwarder's sole function is to inject the Client → Gateway headers on behalf of
MCP clients that do not yet have native gateway support — it is a transitional
compatibility shim, not a permanent architectural component, and it exists only
until MCP clients support specifying a gateway address natively. The reference
implementation is therefore a demonstration of the header conventions themselves,
not of any particular deployment topology.

The implementation will cover:

- **Desktop forwarder:** intercepts local outbound MCP traffic, injects
  `Mcp-Via`, `Mcp-Location`, and `Mcp-Correlation-Id` on behalf of non-gateway-aware
  MCP clients, and rewrites the destination to the configured gateway address
- **Gateway server:** validates the forwarding chain, performs loop detection,
  validates `Mcp-Gateway-Authorization` if configured, appends its own `Mcp-Via`
  and `Mcp-Gateway-Agent` entries, and forwards permitted traffic to the upstream
  MCP server
- **Structured event log:** records a complete audit event per tool call, including
  the full `Mcp-Via` chain, `Mcp-Correlation-Id`, `Mcp-Location`, and `User-Agent`,
  demonstrating end-to-end correlation between gateway audit records and upstream
  MCP server logs

The reference implementation will include latency benchmarks across baseline,
synchronous policy evaluation, and cached policy configurations, to confirm that
header injection and chain validation are consistent with the performance
requirements of production MCP deployments.

---

## Open Questions

1. **`Mcp-Correlation-Id` format:** Should the specification mandate UUID v4, or
   leave the format opaque with a SHOULD recommendation for UUID?

2. **`host` identifier format in `Mcp-Via`:** FQDN, URI, or opaque string? A URI
   provides the most information but may expose internal topology to external
   MCP servers.

3. **`Mcp-Gateway-Agent` capability token registry:** Should a minimal set of
   common capability tokens be standardized in this SEP, or deferred to a future
   SEP as the ecosystem converges?

4. **Response path `Mcp-Via`:** Should response `Mcp-Via` propagation be RECOMMENDED
   rather than OPTIONAL? This would allow clients to verify the return path.

5. **Gateway configuration discovery:** How does an MCP client discover its
   configured gateway address? A companion SEP or extension to SEP-1960 may be
   appropriate.

6. **Attestation JWT:** The mechanism by which MCP servers verify that a claimed
   `Mcp-Via` chain is authentic is deferred. What should the format and trust model
   look like? This is the natural successor to this SEP.

---

## References

**IETF / HTTP Standards**
- RFC 9110 — HTTP Semantics (supersedes RFC 7231) — https://www.rfc-editor.org/rfc/rfc9110
- RFC 9112 — HTTP/1.1 (supersedes RFC 7230, `Via` header) — https://www.rfc-editor.org/rfc/rfc9112
- RFC 7239 — Forwarded HTTP Extension — https://www.rfc-editor.org/rfc/rfc7239
- RFC 6648 — Deprecating the "X-" Prefix — https://www.rfc-editor.org/rfc/rfc6648

**MCP Specification and Community**
- MCP Specification 2025-11-25 — https://modelcontextprotocol.io/specification/2025-11-25
- MCP Extensions — https://modelcontextprotocol.io/extensions/overview
- MCP Transport Working Group Roadmap (2025-12-19) — https://blog.modelcontextprotocol.io/posts/2025-12-19-mcp-transport-future/
- MCP Anniversary and Extensions Release (2025-11-25) — https://blog.modelcontextprotocol.io/posts/2025-11-25-first-mcp-anniversary/
- SEP-2357 — Canonical Media Type for MCP HTTP Transport (`application/mcp+json`)
- SEP-1961 — Mandatory Security Headers for MCP HTTP Transport — https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1961
- SEP-1960 — .well-known/mcp Discovery Endpoint — https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1960
- SEP-1763 — Interceptor Framework for Model Context Protocol — https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1763
- Discussion #804 — Spec Proposal: A Gateway-Based Authorization Model — https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/804
- Discussion #2249 — MCP Enforcement Mode — Mandatory Action Routing for Enterprise Audit & Security — https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2249

**Regulatory and Compliance Frameworks**
- NIST SP 800-53 Rev 5 — Security and Privacy Controls for Information Systems and Organizations
  — https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
  — Control families cited: AC, AU, IA, SC, SI, SR
- NIST SP 800-207 — Zero Trust Architecture
  — https://csrc.nist.gov/publications/detail/sp/800-207/final
- FedRAMP Authorization Framework — https://www.fedramp.gov
- OWASP Top 10 for LLM Applications — LLM02 (Sensitive Information Disclosure),
  LLM06 (Excessive Agency) — https://owasp.org/www-project-top-10-for-large-language-model-applications/

**Industry Research**
- UpGuard — State of Shadow AI Report (2025) — https://www.upguard.com/blog/state-of-shadow-ai
- IBM — Cost of a Data Breach Report (2025) — https://www.ibm.com/reports/data-breach
- Deloitte — State of AI in the Enterprise (2026) — https://www.deloitte.com/us/en/what-we-do/capabilities/applied-artificial-intelligence/content/state-of-ai-in-the-enterprise.html
- EY — Scaling AI in Regulated Industries (2025) — https://www.ey.com/en_us/alliances/scaling-ai-in-regulated-industries

---

## Acknowledgements

This proposal was developed in the context of building enterprise MCP governance
infrastructure, where the absence of a standardized gateway concept and forwarding
chain record was identified as a foundational gap. The NIST SP 800-53 compliance
analysis was developed by mapping the control families required for FedRAMP,
HIPAA, and PCI-DSS authorization to the architectural capabilities that a direct
MCP client-to-server deployment structurally cannot provide — establishing that
the gap is not a configuration problem but a protocol-level absence that requires
a standardized solution.

The design acknowledges and builds on the gateway authorization model proposed in
Discussion #804, and is informed by the Transport Working Group's roadmap toward
stateless, scalable MCP deployments. The `Mcp-Via` convention is deliberately
modeled on twenty-five years of HTTP proxy infrastructure patterns, adapted for
the MCP-specific requirement of an MCP-only chain of custody that generic HTTP
intermediaries cannot contaminate. The minimum-necessary framing was sharpened by
engagement with SEP-1763 and Discussion #2249, which together illustrate the
broader community convergence around enterprise governance requirements for MCP.
