---
name: graphql-idor-via-introspection-leak
description: Covers object-level authorization bypass in GraphQL APIs where introspection reveals hidden fields or mutations that accept arbitrary user/resource IDs without ownership checks. Trigger on keywords like "GraphQL", "query", "mutation", "introspection", "resolver", "node ID", or "object type".
license: MIT
compatibility: Designed for Claude Code. Burp Suite, Insomnia, or GraphQL Voyager recommended.
metadata:
  category: api
  version: "0.1"
  source: original
  source_types: manual
---

# GraphQL IDOR via Introspection Leak Hunting

## Patterns

- GraphQL endpoints that have introspection enabled in production (`__schema`, `__type` queries succeed)
- Resolvers accepting an `id` or `userId` argument with no server-side ownership validation
- Custom scalar types like `ID` or `UUID` passed directly to database queries
- Mutations that update or delete resources using only a client-supplied ID (e.g. `deleteDocument(id: "...")`)
- `node(id: "...")` relay-style interfaces that resolve any global ID regardless of session context
- Batched queries allowing enumeration of multiple IDs in a single request
- Authorization logic applied at the REST layer but missing on the GraphQL resolver layer (dual-stack apps)

## Methodology

1. **Discover the endpoint** — probe `/graphql`, `/api/graphql`, `/v1/graphql`, `/gql`
2. **Run introspection** — send `{ __schema { types { name fields { name args { name type { name } } } } } }` and dump the full schema
3. **Identify object types with ID args** — look for queries/mutations that accept `id`, `userId`, `resourceId`, `ownerId` etc.
4. **Create two test accounts** — Account A (attacker) and Account B (victim)
5. **Grab a victim resource ID** — note an object ID owned by Account B (document, profile, invoice, etc.)
6. **Query as attacker** — from Account A's session, call the resolver with Account B's resource ID
7. **Test mutations too** — attempt `update`, `delete`, `transfer` mutations with cross-account IDs
8. **Test unauthenticated** — remove session token entirely; some resolvers skip auth checks at the GraphQL layer
9. **Confirm impact** — verify you can read, modify, or delete data you don't own

## Key Signals

- Introspection not disabled (`__schema` returns data) → schema is fully readable
- `id` arguments typed as `ID!` or `String!` with no documented ownership constraint
- Objects expose sensitive fields (PII, tokens, internal metadata) retrievable by ID
- App uses Relay global IDs (base64-encoded `TypeName:uuid`) → trivially enumerable
- Error messages like `"Not found"` vs `"Forbidden"` reveal object existence (oracle)
- Batching enabled → can enumerate hundreds of IDs in one request without rate limiting
- Dual-stack architecture (REST + GraphQL backed by same DB) where REST has authz middleware but GraphQL resolvers were added later

## Bypass Techniques

- **Alias batching** — use GraphQL aliases to send 100 ID lookups in one request, bypassing per-request rate limits
  ```graphql
  { a1: user(id: "001") { email } a2: user(id: "002") { email } ... }
  ```
- **Type confusion** — if IDs are integers, try sequential enumeration; if UUIDs, check for Relay base64 encoding
- **Fragment reuse** — use fragments to reduce query size and evade WAF pattern matching on large enum payloads
- **Mutation chaining** — chain a read query + mutation in one request to atomically exfiltrate and modify
- **Variable injection** — move IDs into GraphQL variables instead of inline literals to bypass naive input filters
- **Persisted queries** — if the app supports persisted query IDs, find a stored query that skips authz

## Example Scenarios

### Scenario 1 — Invoice Read IDOR
An invoicing app exposes a `getInvoice(id: ID!)` query. Introspection reveals the field returns `amount`, `clientEmail`, and `lineItems`. Account A queries with an invoice ID belonging to Account B and retrieves full invoice details. No ownership check exists in the resolver — authorization was only enforced on the legacy REST `/invoices/:id` route.

### Scenario 2 — Mutation-Based Account Takeover
A SaaS platform exposes an `updateUserEmail(userId: ID!, newEmail: String!)` mutation. The resolver validates that the session is authenticated but does not verify `userId` matches the session's own user. An attacker updates a victim's email address to one they control, then triggers password reset to complete account takeover.

### Scenario 3 — Unauthenticated Relay Node Leak
An app using Relay exposes a `node(id: ID!)` interface. Global IDs are base64-encoded (`User:1234`). The `node` resolver has no authentication guard. An unauthenticated attacker decodes and re-encodes sequential user IDs, retrieving names, emails, and profile photos for all registered users without a session.

## False Positives

- Introspection returns schema but all resolvers enforce ownership — confirm by actually crossing account boundaries
- `id` argument present but resolver reads the ID from session context, ignoring the supplied value
- `"Not found"` returned for both valid and invalid cross-account IDs — no oracle, no leak
- Relay `node(id:)` returns data but only for public/non-sensitive object types (e.g. public posts)

## Fix Patterns

```js
// WRONG: resolver trusts client-supplied ID
async getInvoice(_, { id }, { db }) {
  return db.invoices.findById(id);
}

// CORRECT: enforce ownership in the query
async getInvoice(_, { id }, { db, currentUser }) {
  const invoice = await db.invoices.findOne({ id, ownerId: currentUser.id });
  if (!invoice) throw new ForbiddenError("Not authorized");
  return invoice;
}
```

- Disable introspection in production (or restrict to authenticated/internal users only)
- Apply authorization at the **resolver level**, not just at the HTTP middleware layer
- Never trust client-supplied IDs — always scope DB queries to the authenticated user's context
- Use a dedicated authorization layer (e.g. graphql-shield, OPA) applied uniformly across all resolvers
- Treat GraphQL as a separate attack surface from REST even when they share the same database
