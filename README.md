# Athena Security Incident Response Queries

A self-contained Terraform stack that turns AWS Config snapshots and CloudTrail logs
into a queryable security data lake — plus 40 pre-built investigation queries and an
optional Okta-protected web dashboard for running them.

Designed for SecOps teams that need fast, SQL-driven answers across an entire AWS
Organization during an incident, audit, or compliance check.

---

## Why

During a security incident you need answers fast:

- "What security groups are open to the internet right now?"
- "Which IAM users have active access keys in account X?"
- "Does this role trust an account outside our org?"
- "Show me every EC2 instance with a public IP."
- "Who logged into the console from this IP address?"
- "What API calls did this compromised access key make?"

Two data sources answer all of these:

- **AWS Config snapshots** — *what resources look like* (current state and configuration).
- **CloudTrail logs** — *who did what and when* (every API call across the org).

This stack stands up an Athena workgroup, a Glue catalog, two tables (with partition
projection), and named queries against both. You query everything from one single account across your org.

<br>

## What's in this stack

```
├── athena-glue.tf                    Athena workgroup, Glue database, Glue tables
├── s3.tf                             Athena query-results bucket
├── waf.tf                            WAFv2 WebACL for the dashboard CloudFront
├── dashboard.tf                      Optional web dashboard (CloudFront + Lambda + API GW)
├── queries-diagnostic.tf             2  diagnostic queries
├── queries-critical.tf               11 critical incident-response queries
├── queries-visibilty_data_gaps.tf    8  visibility / data-exposure queries
├── queries-compliance_inventory.tf   9  compliance & inventory queries
├── queries-cloudtrail.tf             10 CloudTrail API-activity queries
├── modules/
│   ├── s3/                           S3 bucket module (versioning, SSE, public access block)
│   └── waf/                          WAFv2 WebACL module (managed rules + rate limit)
├── dashboard/
│   ├── lambda/athena_dashboard.py    Dashboard backend
│   └── frontend/                     index.html + index.js (login), dashboard.html + dashboard.js (app),
│                                     auth-check.js (CloudFront Function). All JS is external — no inline
│                                     script, so the page runs under a strict `script-src 'self'` CSP.
├── .github/workflows/                CI: trufflehog.yml (secret scan) + trivy.yml (IaC misconfig + CVE scan)
├── _backend.tf                       S3 remote state backend
├── _data.tf                          Data sources + Lambda IAM policy
├── _locals.tf                        Org account IDs, org ID
├── _outputs.tf                       Workgroup, database, results bucket
├── _providers.tf                     AWS provider (us-east-1 + us-west-2 alias)
├── _variables.tf                     All inputs (bucket names, regions, Okta config…)
└── _workspaces.tf                    workspace → IAM role mapping
```

<br>

## Architecture

```
                  Security Account
    ┌──────────────────────────────────────────────────────────┐
    │                                                          │
    │  Athena Workgroup ──► Glue Database ──► Glue Tables      │
    │  (security-ir)        (security_ir)    (config_snapshots │
    │       │                                 cloudtrail_logs) │
    │       ▼                                    │     │       │
    │  S3 query-results                          ▼     ▼       │
    │  (auto-expire 90d)         S3: AWS Config snapshots      │
    │                                                          │
    └──────────────────────────────┬───────────────────────────┘
                                   │ cross-account read
                                   ▼
                  Root / Org-management Account
    ┌──────────────────────────────────────────────────────────┐
    │  S3: org-wide CloudTrail logs                            │
    │  (all org accounts, all regions, multi-region trail)     │
    └──────────────────────────────────────────────────────────┘
```

Config snapshots from every org account land in a Config bucket in the Security
account. CloudTrail logs from the org trail land in a bucket in the Root account; a
bucket policy grants the Security account read access. Both Glue tables use
**partition projection** on `accountid`, `region`, and `dt` — new accounts, regions,
and dates are discovered automatically, no `MSCK REPAIR TABLE` needed.

The optional web dashboard adds CloudFront (with a local WAFv2 WebACL) → S3 static
site → API Gateway HTTP API (JWT-authorized by Okta) → Lambda → Athena.

<br>

## Prerequisites

This stack consumes data — it does not produce it. Before deploying, you need:

1. **AWS Organizations** — the stack reads the org's account list via
   `data "aws_organizations_organization"`. Deploy in the org-management
   account or in an account with `organizations:DescribeOrganization` and
   `organizations:ListAccounts` permissions.
2. **AWS Config** delivering snapshots from every org account to a single S3
   bucket in your Security account. An organization aggregator or
   delivery-channel-per-account both work; this stack only reads the snapshot
   files, not the aggregator API.
3. **An org-wide CloudTrail trail** writing to an S3 bucket — typically in the
   Root / org-management account. Add a bucket policy granting `s3:GetObject`
   and `s3:ListBucket` to the Security account principal that runs Athena.
4. **A Terraform S3 backend** (`bucket` + `dynamodb_table`) — see
   [_backend.tf](_backend.tf).
5. **For the optional dashboard**: a Route53 hosted zone, an Okta OIDC SPA
   client (PKCE flow, no secret), and an Okta group whose members should have
   access.

<br>

## Deployment

1. Edit [_variables.tf](_variables.tf) defaults — at minimum
   `config_bucket_name`, `cloudtrail_bucket_name`, `cloudtrail_s3_prefix`,
   `results_bucket_name`. Adjust `config_regions` / `cloudtrail_regions` to
   match where your Config recorders and CloudTrail trail operate.
2. Edit [_backend.tf](_backend.tf) — point at your Terraform state bucket
   and lock table.
3. Edit [_workspaces.tf](_workspaces.tf) — set the IAM role ARN your
   pipeline assumes for the workspace you'll deploy to.
4. (Dashboard only) edit `dashboard_bucket_name`, `dashboard_domain`,
   `hosted_zone_id`, `okta_issuer_url`, `okta_client_id` in
   [_variables.tf](_variables.tf).
5. Deploy:

   ```bash
   terraform init
   terraform workspace select security    # or whichever you defined
   terraform plan
   terraform apply
   ```

6. Verify by running the diagnostic queries first (see below).

<br>

## Cost

| Item                                | Cost                                                         |
| ----------------------------------- | ------------------------------------------------------------ |
| Saved queries at rest               | **$0** — named queries are stored SQL text                   |
| Query execution                     | **$5.00 per TB scanned** — only when you run a query         |
| Glue Data Catalog                   | **$0** — 1M objects/month free                               |
| Results S3 bucket                   | **~$0** — auto-expires after 90 days, minimal storage        |
| DDL queries (`CREATE TABLE`, etc.)  | **$0** — free                                                |
| Dashboard (CloudFront + Lambda + APIGW) | **<$5/mo** for typical SecOps team usage                 |

| Scenario                                   | Est. Scanned       | Cost     |
| ------------------------------------------ | ------------------ | -------- |
| Single account, 1 day, one resource type   | ~1–10 MB           | <$0.01   |
| Single account, 30 days, all resource types| ~100 MB – 1 GB     | <$0.01   |
| All accounts, 7 days, one resource type    | ~50–500 MB         | <$0.01   |
| All accounts, 30 days, all resource types  | ~1–10 GB           | ~$0.05   |
| Full table scan, no filters (worst case)   | ~10–100 GB         | ~$0.50   |

A **200 GB byte-scan limit** (`bytes_scanned_cutoff`) is enforced on the workgroup
to prevent runaway queries.

<br>

## Saved Queries

All queries are deployed as `aws_athena_named_query` resources and appear in the
Athena console under the `security-incident-response` workgroup.

- **Config queries** — query resource state and configuration from AWS Config snapshots.
- **CloudTrail queries** — query API activity and event logs from the org-wide CloudTrail.

### Diagnostic Queries — [queries-diagnostic.tf](queries-diagnostic.tf)

Run these **first** when Athena returns unexpected empty results. They validate that
partition projection is resolving correctly against your actual S3 path structure.
An empty result means a path or date-format mismatch in the Glue table config — not
that the data doesn't exist.

| Query                              | Description                                                                                                              |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `diag_cloudtrail_partition_check`  | Event counts by account/region/date for the last 3 days of CloudTrail. Empty = path template or `dt` format mismatch.    |
| `diag_config_partition_check`      | Snapshot counts by account/region/date for the last 7 days of Config. Wider window since Config delivers less frequently. |

### Critical Incident Response — [queries-critical.tf](queries-critical.tf)

Core queries for active security incidents. All use the Config snapshots table
(point-in-time resource state).

| Query                              | Description                                                                                                                  |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `iam_users_all`                    | All IAM users across all accounts with creation dates. IAM is global — only scans us-east-1.                                 |
| `iam_access_keys_active`           | IAM users with active access keys. Keys created after the last snapshot won't appear.                                        |
| `iam_policies_admin_access`        | Users / roles / groups with AdministratorAccess or broad wildcard (`Action:* Resource:*`) policies.                          |
| `iam_roles_cross_account_trust`    | IAM roles that trust other AWS accounts via `sts:AssumeRole`. Does not detect SAML/OIDC federation.                          |
| `security_groups_open_ingress`     | Security groups with ANY inbound rule open to `0.0.0.0/0` or `::/0`. High volume — ALB/NLB legitimately use this on 80/443.  |
| `security_groups_open_ssh_rdp`     | Security groups with SSH (22), RDP (3389), or all-traffic (`-1`) open to the internet. More targeted — common attacker doors.|
| `public_ec2_instances`             | EC2 instances with a public IP. Shows running and stopped. Does not show ELB/NAT gateway public IPs.                         |
| `s3_buckets_public`                | Buckets with public ACLs, AuthenticatedUsers grants, or incomplete public access blocks. **Does not check bucket policies.** |
| `ec2_instances_by_account_region`  | Full EC2 inventory. Uncomment filter lines to search by private IP or instance ID. Always add partition filters.             |
| `resource_config_by_id`            | Look up the full Config JSON for any resource by ID or ARN. **Parameterized** — replace `RESOURCE_ID_HERE`.                  |
| `iam_access_key_lookup`            | Find which IAM user owns a specific access key. **Parameterized** — replace `ACCESS_KEY_ID_HERE`.                            |

### Visibility Gaps & Data Exposure — [queries-visibilty_data_gaps.tf](queries-visibilty_data_gaps.tf)

Queries for missing security controls and unencrypted resources.

| Query                          | Description                                                                                                                       |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `iam_users_mfa_disabled`       | IAM users with no MFA device. Includes console and API-only users. IAM is global — only scans us-east-1.                          |
| `iam_users_console_no_mfa`     | IAM users with console login enabled but no MFA. Highest-risk accounts. Does not include federated/SSO users.                     |
| `vpc_flow_log_status`          | VPCs without VPC-level flow logs. **WARNING:** CTE scans the table twice — add partition filters to BOTH the CTE and main query. |
| `s3_buckets_no_encryption`     | Buckets without explicit default encryption. Since Jan 2023 AWS applies SSE-S3 by default to new objects.                         |
| `s3_buckets_no_logging`        | Buckets without server access logging. Blind spots during incident investigation.                                                 |
| `ec2_instances_no_imdsv2`      | EC2 instances not enforcing IMDSv2 (`httpTokens != required`). IMDSv1 is SSRF-vulnerable. `optional` still allows v1.             |
| `rds_instances_public`         | RDS instances with `publiclyAccessible = true`. Actual reachability depends on SGs and subnet routing.                            |
| `rds_instances_no_encryption`  | RDS instances without storage encryption. Can't be added in place — requires snapshot/restore.                                    |

### Compliance & Inventory — [queries-compliance_inventory.tf](queries-compliance_inventory.tf)

Compliance posture, resource inventory, operational visibility.

| Query                            | Description                                                                                                            |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `lambda_functions_inventory`     | Lambda inventory with runtime, memory, timeout, code size, execution role. Find deprecated runtimes.                   |
| `s3_buckets_versioning_disabled` | Buckets without versioning (never-enabled and suspended). Can't recover from accidental deletes.                       |
| `ebs_volumes_unencrypted`        | Unencrypted EBS volumes. Can't add encryption in place. Shows attachment status to identify affected instances.        |
| `ebs_volumes_unattached`         | EBS volumes in `available` state — orphaned from terminated instances, costing money, possibly holding sensitive data. |
| `rds_instances_no_multi_az`      | RDS without Multi-AZ. No automatic failover.                                                                           |
| `resource_count_by_type`         | Counts all resources by type across the org. Add `dt` filter to limit to a snapshot date.                              |
| `resource_count_by_account`      | Counts resources by account with totals and distinct resource types. Identify largest footprints.                      |
| `tagged_resources_audit`         | Resources missing required tags. Adjust tag key names in the SQL to match your policy.                                 |
| `config_snapshot_timeline`       | Snapshot delivery timeline per account/region. Gaps indicate Config recorder issues.                                   |

### CloudTrail API Activity — [queries-cloudtrail.tf](queries-cloudtrail.tf)

Queries against the `cloudtrail_logs` table. Each row is already one API event — no
`UNNEST` needed. Dates are **zero-padded** (`dt = '2025/01/15'`, not `'2025/1/15'`).

**Always use partition filters on CloudTrail.** The table is much larger than Config.

| Query                          | Description                                                                                                                |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `ct_console_logins`            | All console login events (success and failure) with source IP, MFA status, result. Start here for unauthorized access.     |
| `ct_failed_console_logins`     | Failed console logins. Multiple failures from one IP = brute force. Multiple failures for one user = credential stuffing.  |
| `ct_iam_changes`               | IAM user/role/policy changes. Look for attacker persistence (new users, roles, keys). IAM events are logged in us-east-1.  |
| `ct_root_account_usage`        | Root account API activity. Root should rarely be used — any activity warrants investigation. Filters out service events.   |
| `ct_unauthorized_api_calls`    | API calls returning `AccessDenied` / `UnauthorizedAccess`. Bursts from one principal = recon / permission probing.         |
| `ct_security_group_changes`    | SG creation, deletion, rule changes. Look for rules opened to `0.0.0.0/0` or unexpected port ranges during an incident.    |
| `ct_s3_access_changes`         | Bucket policy, ACL, and public access block changes. Removed policies / opened ACLs / disabled blocks = data exposure.     |
| `ct_cloudtrail_tampering`      | CloudTrail stop, delete, update events. Attacker's first move is often disabling logging. **Always investigate.**          |
| `ct_credential_usage_by_ip`    | All API calls made by a specific credential. **Parameterized** — replace `ACCESS_KEY_OR_ARN_HERE` (`AKIA…` or principal ARN). |
| `ct_kms_key_changes`           | KMS key disable/delete/policy changes. Can make encrypted data unrecoverable or grant unauthorized decrypt.                |

<br>

## How to Use

### Running a saved query

1. Log into the **Security account** AWS Console.
2. Navigate to **Amazon Athena** → **Query editor**.
3. Select the `security-incident-response` workgroup (top right). Click
   **Acknowledge** when prompted.
4. Click the **Saved queries** tab.
5. Select a query. **If the query starts with `ct_`, you MUST add partition
   filters** to keep costs down.
6. Uncomment the filter lines near the bottom of the query (delete the `--`)
   and adjust the values.
7. Click **Run**.

Once you have results, close the query. **Do not click Save** — that would overwrite
the named query, and the next `terraform apply` would revert it.

### Narrowing results with partition filters

Every query includes commented-out partition filter examples. Adding them drastically
reduces data scanned (and cost).

**Config queries** (non-zero-padded dates):

```sql
AND accountid = '123456789012'
AND dt        = '2025/7/1'
AND dt        BETWEEN '2025/7/1' AND '2025/7/7'
AND region    = 'us-east-1'
```

**CloudTrail queries** (zero-padded dates):

```sql
AND accountid = '123456789012'
AND dt        = '2025/01/15'
AND dt        BETWEEN '2025/01/01' AND '2025/01/07'
AND region    = 'us-east-1'
```

### Config query pattern

Config rows wrap an array of items in `configurationitems`. Flatten with UNNEST,
then filter:

```sql
SELECT ci.*
FROM   security_incident_response.config_snapshots
       CROSS JOIN UNNEST(configurationitems) AS t(ci)
WHERE  ci.resourcetype = 'AWS::EC2::SecurityGroup'
   AND accountid       = '123456789012'
   AND dt              = '2025/7/1'
```

The `configuration` column is a JSON string. Extract fields with Athena's JSON
functions:

```sql
json_extract_scalar(ci.configuration, '$.publicIpAddress')   -- single value
json_extract(ci.configuration,        '$.ipPermissions')     -- nested object/array
```

### CloudTrail query pattern

Each row is one API event:

```sql
SELECT eventtime, eventname, useridentity.arn AS principal_arn, sourceipaddress
FROM   security_incident_response.cloudtrail_logs
WHERE  eventname  = 'ConsoleLogin'
   AND accountid  = '123456789012'
   AND dt         = '2025/01/15'
```

Use `json_extract_scalar` on string columns like `requestparameters`, `responseelements`,
`additionaleventdata`:

```sql
json_extract_scalar(additionaleventdata, '$.MFAUsed')
json_extract_scalar(responseelements,    '$.ConsoleLogin')
```

<br>

## Making Custom Queries

You can add queries two ways: **terraform-managed** (durable, code-reviewed, shared
with the team) or **dashboard-saved** (fast, ad hoc, no deploy required).

### Option 1 — Terraform (permanent)

1. Pick the file that matches your query's purpose
   (e.g. [queries-critical.tf](queries-critical.tf) for incident-response queries).
2. Add a new `aws_athena_named_query` block. Follow the existing pattern — `name`,
   `description`, `query` (heredoc).
3. Always include commented-out partition filters at the bottom of the SQL —
   users will need them.
4. For parameterized queries, use an `ALL_CAPS_PLACEHOLDER` token; the dashboard
   auto-detects these and renders an input field.

Skeleton:

```hcl
resource "aws_athena_named_query" "my_new_query" {
  name        = "my_new_query"
  description = "One-sentence summary of what this finds and any caveats."
  database    = aws_glue_catalog_database.security_ir.name
  workgroup   = aws_athena_workgroup.security_ir.name

  query = <<-EOT
    SELECT ci.resourceid, ci.awsregion
    FROM   ${aws_glue_catalog_database.security_ir.name}.config_snapshots
           CROSS JOIN UNNEST(configurationitems) AS t(ci)
    WHERE  ci.resourcetype = 'AWS::Lambda::Function'
        -- AND accountid = '123456789012'
        -- AND dt        = '2025/7/1'
        -- AND region    = 'us-east-1'
  EOT
}
```

Then `terraform plan` / `terraform apply`. The query appears in the workgroup and
on the dashboard immediately.

### Option 2 — Dashboard (ad hoc)

1. Open the dashboard in the browser, sign in.
2. Click **New Query** — pick the Config or CloudTrail starter template.
3. Write your SQL. The backend only allows read-only `SELECT`/`WITH` queries
   (DDL/DML is blocked), so you can't accidentally break the catalog.
4. Click **Save as Custom Query** to share it across the team. Custom queries are
   stored as Athena named queries with a `custom_` prefix — they appear alongside
   the pre-built ones for everyone with dashboard access.
5. Use **Delete** to remove a custom query. Pre-built queries (no `custom_` prefix)
   are protected from deletion.

Custom queries persist across `terraform apply` because the Lambda role creates
them with the `custom_` prefix, and the named queries managed by this stack don't
use that prefix.

<br>

## Cross-Account Access (CloudTrail bucket)

The CloudTrail logs live in the Root / org-management account. The Security account
needs read access. Add two statements to the CloudTrail bucket policy:

```json
{
  "Sid":       "AthenaSecurityAccountGetObjects",
  "Effect":    "Allow",
  "Principal": { "AWS": "arn:aws:iam::SECURITY_ACCOUNT_ID:root" },
  "Action":    "s3:GetObject",
  "Resource":  "arn:aws:s3:::YOUR-CLOUDTRAIL-BUCKET/*"
},
{
  "Sid":       "AthenaSecurityAccountListBucket",
  "Effect":    "Allow",
  "Principal": { "AWS": "arn:aws:iam::SECURITY_ACCOUNT_ID:root" },
  "Action":    ["s3:ListBucket", "s3:GetBucketLocation"],
  "Resource":  "arn:aws:s3:::YOUR-CLOUDTRAIL-BUCKET"
}
```

The Config bucket lives in the Security account already, so no cross-account policy
is needed for it.

---

## Athena Security Dashboard

An optional, interactive web dashboard that lets the team run the 40 pre-built
queries and create custom queries without logging into the AWS console. Select a
query, tune parameters, click Run, see live results in the browser.

### Dashboard Architecture

```
User → CloudFront (HTTPS, ACM cert, WAF, security headers)
     → CloudFront Function (viewer-request: JWT cookie validation)
     → S3 origin (OAI access, not public)
     → index.html + index.js  (login — minimal, Okta PKCE only)
     → Okta OIDC auth
     → dashboard.html + dashboard.js  (full app, loaded only after auth)
       (JS is external — strict `script-src 'self'` CSP, no inline script)
     → API Gateway HTTP API (JWT authorizer)
     → Lambda (Python 3.12)
     → Athena → Glue → S3 data buckets
```

### Security

- **Okta OIDC** — SPA app with PKCE (no client secret). After auth, the `id_token`
  is stored in both localStorage (for client-side checks) and a `Secure;
  SameSite=Strict` cookie (for CloudFront Function validation). API Gateway
  re-validates the JWT — with full cryptographic signature verification against
  Okta's JWKS — on every API request.
- **Okta group restriction** — only users in your designated Okta group can authenticate.
  To grant/revoke access, add/remove users from the Okta group — no Terraform change.
- **CloudFront Function auth gate** — [auth-check.js](dashboard/frontend/auth-check.js)
  runs on every viewer-request and validates the JWT cookie (`athena_token`).
  Protected paths return 403 without a valid, non-expired token from the
  configured Okta issuer. Public paths (`/`, `/index.html`, `/index.js`,
  `/robots.txt`, `/.well-known/security.txt`) are exempt — note `dashboard.js`
  is **not** public, so the app logic only loads for authenticated users.
  CloudFront Functions cannot make
  network calls, so this layer validates structure + `exp` + `iss` only —
  API Gateway's JWT authorizer handles cryptographic signature verification.
- **WAF** — local WAFv2 WebACL ([modules/waf](modules/waf/)) with AWS managed rule
  groups (`CommonRuleSet`, `KnownBadInputsRuleSet`, `AmazonIpReputationList`,
  `AnonymousIpList`) plus a per-IP rate limit. CloudFront-scoped, lives in us-east-1.
- **CloudFront** — HTTPS only with ACM cert (TLS 1.2_2021 minimum), HSTS
  (preload), X-Frame-Options `DENY`, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy. S3 metadata headers stripped.
- **Content Security Policy** — strict `script-src 'self'` (no `unsafe-inline`):
  all JavaScript is served as external files, so there are no inline scripts or
  inline event handlers to exploit. Also sets `object-src 'none'`,
  `frame-ancestors 'none'`, `base-uri 'self'`, and a `connect-src` allowlist
  limited to the Okta issuer and the API Gateway endpoint.
- **S3** — fully locked down via OAI. Bucket has no public access.
- **SQL validation** — the Lambda enforces a read-only **allowlist** on both the
  run and save paths: a query must start with `SELECT` or `WITH` (CTE), or it is
  rejected. SQL comments are stripped before the check so keyword-splitting
  evasions (e.g. `CREATE/**/TABLE`) can't slip through, and a defense-in-depth
  blocklist catches DDL/DML constructs
  (`CREATE`/`DROP`/`ALTER TABLE|VIEW`, `UNLOAD`, `INSERT INTO`, `DELETE FROM`,
  `GRANT`, etc.). This sits behind least-privilege IAM (Glue read-only, no
  `CreateTable`) and the workgroup's `enforce_workgroup_configuration`, so even a
  bypass cannot modify the catalog or write outside the results prefix.
- **Split frontend** — login page (`index.html`) is minimal, no business logic.
  Dashboard (`dashboard.html`) loaded only after auth.
- **XSS protection** — all dynamic HTML goes through `esc()` (text content) /
  `escAttr()` (attribute values) encoders, backed by the strict CSP above.
- **CSV export safety** — exported result cells are guarded against spreadsheet
  formula injection (a leading `= + - @` is neutralized) so query data can't
  execute when the CSV is opened in Excel/Sheets.
- **CORS** — a single source of truth: the API Gateway `cors_configuration`
  (origin locked to the dashboard domain) answers preflight and sets the
  `Access-Control-Allow-*` headers; the Lambda does not duplicate them.
- **Error handling** — API responses return generic error messages; full
  exception detail is written only to CloudWatch logs, so internal infrastructure
  details (ARNs, bucket names) are never disclosed to the browser.
- **Audit logging** — every query execution and custom-query save/delete is
  logged with the authenticated user identity.

### Dashboard Features

- **40 pre-built queries** across 5 categories with enhanced descriptions
- **Search bar** — real-time filtering on query name and description
- **Custom queries** — save / delete; shared across users via Athena named
  queries (`custom_` prefix)
- **New Query templates** — CloudTrail and Config starter templates with
  inline instructions
- **User guide** — accessible via "? Guide" link; covers data sources,
  partition filters, query patterns, JSON extraction, and a worked example
- **Parameterized queries** — `ALL_CAPS_HERE` placeholders auto-render as
  input fields

### API Routes

All routes require JWT authorization (Okta `id_token`).

| Route                         | Description                                                          |
| ----------------------------- | -------------------------------------------------------------------- |
| `GET /queries`                | List all named queries (pre-built + custom) grouped by category      |
| `POST /query/start`           | Start a query execution (read-only `SELECT`/`WITH` only)             |
| `GET /query/status/{id}`      | Poll execution status + bytes scanned                                |
| `GET /query/results/{id}`     | Fetch paginated results (1000 rows / page)                           |
| `POST /query/stop/{id}`       | Cancel a running query execution                                     |
| `POST /query/save`            | Save a custom named query (`custom_` prefix enforced)                |
| `DELETE /query/custom/{id}`   | Delete a custom query (pre-built queries protected)                  |

---

## Continuous Security Scanning

Two GitHub Actions workflows run on every pull request to `main`
([.github/workflows/](.github/workflows/)):

| Workflow          | Tool                | What it scans                                                       |
| ----------------- | ------------------- | ------------------------------------------------------------------- |
| `trufflehog.yml`  | TruffleHog          | All files for leaked/verified secrets (no path filter)              |
| `trivy.yml`       | Trivy (filesystem)  | Terraform for IaC misconfigurations + CVEs in dependencies          |

Trivy runs in filesystem mode (`misconfig,vuln` scanners) — there is no container
image in this stack — and reports HIGH/CRITICAL findings to the GitHub **Security**
tab via SARIF. Both workflows are non-blocking (they report rather than fail the
build) and Trivy also runs on a weekly schedule so newly-published CVEs and checks
are caught without a code change. Secret scanning is owned solely by TruffleHog, so
Trivy's secret scanner is intentionally disabled to avoid duplicate findings.

## Modules

| Name              | Source              | Purpose                                                             |
| ----------------- | ------------------- | ------------------------------------------------------------------- |
| `athena_results`  | `./modules/s3`      | S3 bucket for Athena query results (90-day lifecycle expiration)    |
| `dashboard_s3`    | `./modules/s3`      | S3 bucket for the dashboard static frontend (CloudFront origin)     |
| `dashboard_waf`   | `./modules/waf`     | CloudFront-scoped WAFv2 WebACL for the dashboard distribution       |

Both modules are vendored in this repo with no external dependencies — you can
deploy this stack standalone.

## Requirements

| Name      | Version           |
| --------- | ----------------- |
| terraform | >= 1.15.6         |
| aws       | >= 6.0.0, < 7.0.0 |
| archive   | >= 2.0.0          |

## Inputs

| Name                       | Description                                                             | Type           | Default                                            |
| -------------------------- | ----------------------------------------------------------------------- | -------------- | -------------------------------------------------- |
| `service_name`             | Tag applied to all resources                                            | `string`       | `"Athena-Security-Queries"`                        |
| `owning_team`              | Tag applied to all resources                                            | `string`       | `"SecOps"`                                         |
| `automation_tf`            | Tag applied to all resources                                            | `string`       | `"Terraform"`                                      |
| `config_bucket_name`       | S3 bucket containing AWS Config snapshots                               | `string`       | `"company-config"`                                 |
| `config_s3_prefix`         | S3 key prefix for Config delivery channel data                          | `string`       | `"config"`                                         |
| `config_regions`           | Regions monitored by Config                                             | `list(string)` | `["us-east-1","us-east-2","us-west-1","us-west-2"]`|
| `cloudtrail_bucket_name`   | S3 bucket containing org-wide CloudTrail logs (Root account)            | `string`       | `"company-org-cloudtrail"`                         |
| `cloudtrail_s3_prefix`     | S3 key prefix for CloudTrail delivery                                   | `string`       | `"company-org"`                                    |
| `cloudtrail_regions`       | Regions for CloudTrail partition projection (all standard regions)      | `list(string)` | All standard AWS regions                           |
| `results_bucket_name`      | S3 bucket for Athena query results                                      | `string`       | `"company-athena-security-results"`                |
| `results_expiration_days`  | Days to retain Athena query results before auto-deletion                | `number`       | `90`                                               |
| `bytes_scanned_cutoff`     | Per-query byte-scan cutoff (cancels runaway queries)                    | `number`       | `214748364800` (200 GB)                            |
| `dashboard_bucket_name`    | S3 bucket name for the dashboard static site                            | `string`       | `"company-athena-dashboard.security.example.com"`  |
| `dashboard_domain`         | Public domain name for the dashboard                                    | `string`       | `"company-athena-dashboard.security.example.com"`  |
| `hosted_zone_id`           | Route53 hosted zone ID for the dashboard domain                         | `string`       | `"Z00000000000000000000"`                          |
| `okta_issuer_url`          | Okta OIDC issuer URL                                                    | `string`       | `"https://example.okta.com"`                       |
| `okta_client_id`           | Okta OIDC SPA client ID (not sensitive)                                 | `string`       | `"0oaEXAMPLECLIENTID00"`                           |
| `workspace_iam_roles`      | Map of workspace name → IAM role ARN your TF pipeline assumes           | `map`          | see [_workspaces.tf](_workspaces.tf)               |

## Outputs

| Name                    | Description                                       |
| ----------------------- | ------------------------------------------------- |
| `athena_workgroup_name` | Name of the Athena workgroup for security queries |
| `glue_database_name`    | Name of the Glue catalog database                 |
| `results_bucket_name`   | S3 bucket storing Athena query results            |

---

## License

See [LICENSE](LICENSE).
