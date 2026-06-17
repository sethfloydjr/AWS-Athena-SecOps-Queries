"""
Athena Security Dashboard — Lambda Backend

Routes:
  GET    /queries           — list all named queries grouped by category
  POST   /query/start       — start a query execution
  GET    /query/status/{id} — poll execution status
  GET    /query/results/{id} — fetch paginated results
  POST   /query/save        — save a custom named query (prefixed with custom_)
  DELETE /query/custom/{id} — delete a custom named query
"""

import json
import logging
import os
import re
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

WORKGROUP = os.environ.get("WORKGROUP", "security-incident-response")
DATABASE = os.environ.get("DATABASE", "security_incident_response")
RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "company-athena-security-results")
MAX_RESULT_ROWS = int(os.environ.get("MAX_RESULT_ROWS", "1000"))

athena = boto3.client("athena")

CUSTOM_PREFIX = "custom_"

# Exact name → category overrides for queries whose prefix would miscategorize them.
# Checked first; prefix map is the fallback.
CATEGORY_EXACT = {
    "s3_buckets_public": "Critical Incident Response",
    "security_groups_open_ingress": "Critical Incident Response",
    "security_groups_open_ssh_rdp": "Critical Incident Response",
    "ec2_instances_by_account_region": "Critical Incident Response",
    "public_ec2_instances": "Critical Incident Response",
    "iam_users_mfa_disabled": "Visibility & Data Gaps",
    "iam_users_console_no_mfa": "Visibility & Data Gaps",
    "ec2_instances_no_imdsv2": "Visibility & Data Gaps",
    "resource_count_by_type": "Compliance & Inventory",
    "resource_count_by_account": "Compliance & Inventory",
    "config_snapshot_timeline": "Compliance & Inventory",
    "tagged_resources_audit": "Compliance & Inventory",
}

# Prefix-based fallback for queries not in the exact map
CATEGORY_PREFIX = {
    "diag_": "Diagnostics",
    "ct_": "CloudTrail API Activity",
    "iam_": "Critical Incident Response",
    "resource_": "Critical Incident Response",
    "s3_": "Visibility & Data Gaps",
    "vpc_": "Visibility & Data Gaps",
    "rds_": "Visibility & Data Gaps",
    "lambda_": "Compliance & Inventory",
    "ebs_": "Compliance & Inventory",
}

# Pattern for detecting template parameters (ALL_CAPS_WITH_UNDERSCORES)
PARAM_PATTERN = re.compile(r"\b[A-Z][A-Z0-9_]{2,}_HERE\b")

# SQL allowlist — only read-only SELECT / WITH (CTE) statements are permitted.
# This is the primary control: a statement that does not begin with SELECT or
# WITH is rejected outright, so CTAS, UNLOAD, CREATE VIEW, GRANT, etc. never run.
ALLOWED_START = re.compile(r"^\s*(SELECT|WITH)\b", re.IGNORECASE)

# SQL blocklist — defense in depth behind the allowlist. Matches DDL/DML as
# multi-keyword constructs (not bare keywords) so it does not false-positive on
# data such as eventname LIKE '%Create%' or a column named "update_time". The
# allowlist already guarantees the statement starts with SELECT/WITH; this layer
# catches anything that slips past via a stacked statement or unusual whitespace.
BLOCKED_SQL = re.compile(
    r"\b("
    r"CREATE[\s/]+(TABLE|EXTERNAL|VIEW|OR[\s/]+REPLACE)"
    r"|UNLOAD[\s/]*\("
    r"|INSERT[\s/]+INTO"
    r"|DROP[\s/]+(TABLE|VIEW|DATABASE|SCHEMA)"
    r"|ALTER[\s/]+(TABLE|VIEW|DATABASE|SCHEMA)"
    r"|MSCK[\s/]+REPAIR"
    r"|DELETE[\s/]+FROM"
    r"|UPDATE[\s/]+\w"
    r"|MERGE[\s/]+INTO"
    r"|GRANT[\s/]+\w"
    r"|REVOKE[\s/]+\w"
    r"|PREPARE[\s/]+\w"
    r")\b",
    re.IGNORECASE
)

# SQL comment patterns. We strip comments to a single space BEFORE running the
# allowlist/blocklist so that comment-splitting evasions collapse back to plain
# keywords — e.g. "CREATE/**/TABLE" and "CREATE--\nTABLE" both become
# "CREATE TABLE" and are caught. Comments are stripped only for this security
# check; the original SQL (comments intact) is what actually executes.
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"--[^\n]*")


def strip_sql_comments(sql):
    """Replace SQL comments with spaces so keyword-splitting evasions collapse."""
    sql = _BLOCK_COMMENT.sub(" ", sql)
    sql = _LINE_COMMENT.sub(" ", sql)
    return sql

# Friendly labels for known parameters
PARAM_LABELS = {
    "ACCESS_KEY_ID_HERE": "Access Key ID (e.g. AKIA...)",
    "RESOURCE_ID_HERE": "Resource ID or ARN",
    "ACCESS_KEY_OR_ARN_HERE": "Access Key or Role ARN",
}


def categorize_query(name):
    """Assign a category — checks exact name first, then prefix fallback."""
    if name.startswith(CUSTOM_PREFIX):
        return "Custom Queries"
    if name in CATEGORY_EXACT:
        return CATEGORY_EXACT[name]
    for prefix, category in CATEGORY_PREFIX.items():
        if name.startswith(prefix):
            return category
    return "Other"


def detect_parameters(sql):
    """Find template parameters in SQL and return them with labels."""
    params = PARAM_PATTERN.findall(sql)
    return [
        {"name": p, "label": PARAM_LABELS.get(p, p.replace("_", " ").title())}
        for p in sorted(set(params))
    ]


def handle_list_queries(event):
    """GET /queries — list all named queries grouped by category."""
    query_ids = []
    next_token = None

    while True:
        kwargs = {"WorkGroup": WORKGROUP}
        if next_token:
            kwargs["NextToken"] = next_token
        response = athena.list_named_queries(**kwargs)
        query_ids.extend(response.get("NamedQueryIds", []))
        next_token = response.get("NextToken")
        if not next_token:
            break

    if not query_ids:
        return response_json(200, {"categories": {}})

    # Batch get named queries (max 50 per call)
    queries = []
    for i in range(0, len(query_ids), 50):
        batch = query_ids[i:i + 50]
        result = athena.batch_get_named_query(NamedQueryIds=batch)
        queries.extend(result.get("NamedQueries", []))

    # Group by category
    categories = {}
    for q in sorted(queries, key=lambda x: x["Name"]):
        cat = categorize_query(q["Name"])
        if cat not in categories:
            categories[cat] = []
        categories[cat].append({
            "id": q["NamedQueryId"],
            "name": q["Name"],
            "description": q.get("Description", ""),
            "sql": q["QueryString"],
            "database": q.get("Database", DATABASE),
            "parameters": detect_parameters(q["QueryString"]),
            "isCustom": q["Name"].startswith(CUSTOM_PREFIX),
        })

    return response_json(200, {"categories": categories})


def get_user_from_event(event):
    """Extract the authenticated user's identity from the JWT claims in the API Gateway event."""
    try:
        claims = event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})
        return claims.get("email", claims.get("sub", "unknown"))
    except Exception:
        return "unknown"


def handle_start_query(event):
    """POST /query/start — start a query execution."""
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return response_json(400, {"error": "Invalid JSON body"})

    sql = body.get("sql", "").strip()
    if not sql:
        return response_json(400, {"error": "Missing 'sql' field"})

    # Validate against comment-stripped SQL so commented-out keyword splitting
    # (e.g. CREATE/**/TABLE) cannot evade the checks. Only read-only statements
    # are allowed: the query must start with SELECT/WITH (allowlist) and must
    # not contain a DDL/DML construct (blocklist, defense in depth).
    sql_check = strip_sql_comments(sql)
    if not ALLOWED_START.match(sql_check) or BLOCKED_SQL.search(sql_check):
        user = get_user_from_event(event)
        logger.warning(f"BLOCKED prohibited SQL from {user}: {sql[:200]}")
        return response_json(403, {"error": "Only read-only SELECT queries are allowed. The statement must start with SELECT or WITH; CREATE, UNLOAD, INSERT, DROP, ALTER, and other DDL/DML statements are blocked."})

    # Database is hardcoded — never accept from user input to prevent
    # querying tables in other Glue databases
    try:
        result = athena.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={"Database": DATABASE},
            WorkGroup=WORKGROUP,
            ResultConfiguration={
                "OutputLocation": f"s3://{RESULTS_BUCKET}/results/",
            },
        )
        execution_id = result["QueryExecutionId"]
        user = get_user_from_event(event)
        logger.info(f"Query started by {user}: {execution_id} — SQL: {sql[:200]}")
        return response_json(200, {"executionId": execution_id})
    except Exception as e:
        logger.error(f"Failed to start query: {e}")
        return response_json(500, {"error": "Failed to start query execution."})


def handle_query_status(event):
    """GET /query/status/{id} — poll execution status."""
    execution_id = event.get("pathParameters", {}).get("id", "")
    if not execution_id:
        return response_json(400, {"error": "Missing execution ID"})

    try:
        result = athena.get_query_execution(QueryExecutionId=execution_id)
        execution = result["QueryExecution"]
        status = execution["Status"]
        stats = execution.get("Statistics", {})

        response_data = {
            "executionId": execution_id,
            "state": status["State"],
            "stateChangeReason": status.get("StateChangeReason", ""),
            "bytesScanned": stats.get("DataScannedInBytes", 0),
            "executionTimeMs": stats.get("EngineExecutionTimeInMillis", 0),
        }

        return response_json(200, response_data)
    except Exception as e:
        logger.error(f"Failed to get query status: {e}")
        return response_json(500, {"error": "Failed to retrieve query status."})


def handle_query_results(event):
    """GET /query/results/{id} — fetch paginated results.

    SECURITY NOTE: Results are not scoped per-user. Any authenticated user can
    fetch results for any QueryExecutionId in the workgroup. This is a deliberate
    shared-team design decision — all users in the Okta group have the same
    access level to the same data. All query executions are logged with user
    identity in handle_start_query for audit purposes.
    """
    execution_id = event.get("pathParameters", {}).get("id", "")
    if not execution_id:
        return response_json(400, {"error": "Missing execution ID"})

    next_token = event.get("queryStringParameters", {}) or {}
    next_token = next_token.get("nextToken")

    try:
        kwargs = {
            "QueryExecutionId": execution_id,
            "MaxResults": MAX_RESULT_ROWS,
        }
        if next_token:
            kwargs["NextToken"] = next_token

        result = athena.get_query_results(**kwargs)
        result_set = result["ResultSet"]

        # Extract column names from first row (header)
        columns = [col["Name"] for col in result_set["ResultSetMetadata"]["ColumnInfo"]]

        # Extract data rows (skip header row if no NextToken — first page includes header)
        rows = []
        raw_rows = result_set.get("Rows", [])
        start_idx = 1 if not next_token and len(raw_rows) > 0 else 0

        for row in raw_rows[start_idx:]:
            values = [datum.get("VarCharValue", "") for datum in row.get("Data", [])]
            rows.append(dict(zip(columns, values)))

        response_data = {
            "columns": columns,
            "rows": rows,
            "rowCount": len(rows),
            "nextToken": result.get("NextToken"),
        }

        return response_json(200, response_data)
    except Exception as e:
        logger.error(f"Failed to get query results: {e}")
        return response_json(500, {"error": "Failed to retrieve query results."})


def handle_save_query(event):
    """POST /query/save — save a custom named query."""
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return response_json(400, {"error": "Invalid JSON body"})

    name = body.get("name", "").strip()
    description = body.get("description", "").strip()
    sql = body.get("sql", "").strip()

    if not name:
        return response_json(400, {"error": "Name is required"})
    if not description:
        return response_json(400, {"error": "Description is required"})
    if not sql:
        return response_json(400, {"error": "SQL is required"})

    # Apply the same read-only allowlist as /query/start so a DDL/DML statement
    # can't be persisted into the catalog (it could never be run anyway, and
    # keeps the save and execute paths consistent).
    sql_check = strip_sql_comments(sql)
    if not ALLOWED_START.match(sql_check) or BLOCKED_SQL.search(sql_check):
        user = get_user_from_event(event)
        logger.warning(f"BLOCKED prohibited SQL on save from {user}: {sql[:200]}")
        return response_json(403, {"error": "Only read-only SELECT/WITH queries can be saved. CREATE, UNLOAD, INSERT, DROP, ALTER, and other DDL/DML statements are blocked."})

    # Enforce custom_ prefix
    if not name.startswith(CUSTOM_PREFIX):
        name = CUSTOM_PREFIX + name

    try:
        result = athena.create_named_query(
            Name=name,
            Description=description,
            Database=DATABASE,
            QueryString=sql,
            WorkGroup=WORKGROUP,
        )
        query_id = result["NamedQueryId"]
        user = get_user_from_event(event)
        logger.info(f"Custom query created by {user}: {name} ({query_id})")
        return response_json(200, {"id": query_id, "name": name})
    except Exception as e:
        logger.error(f"Failed to save custom query: {e}")
        return response_json(500, {"error": "Failed to save custom query."})


def handle_delete_custom_query(event):
    """DELETE /query/custom/{id} — delete a custom named query."""
    query_id = event.get("pathParameters", {}).get("id", "")
    if not query_id:
        return response_json(400, {"error": "Missing query ID"})

    # Verify it's a custom query before deleting
    try:
        result = athena.get_named_query(NamedQueryId=query_id)
        query_name = result["NamedQuery"]["Name"]
        if not query_name.startswith(CUSTOM_PREFIX):
            return response_json(403, {"error": "Cannot delete pre-built queries"})
    except Exception as e:
        logger.error(f"Failed to verify query: {e}")
        return response_json(404, {"error": "Query not found"})

    try:
        athena.delete_named_query(NamedQueryId=query_id)
        user = get_user_from_event(event)
        logger.info(f"Custom query deleted by {user}: {query_name} ({query_id})")
        return response_json(200, {"deleted": query_id})
    except Exception as e:
        logger.error(f"Failed to delete custom query: {e}")
        return response_json(500, {"error": "Failed to delete custom query."})


def response_json(status_code, body):
    """Return a properly formatted API Gateway response.

    CORS headers are intentionally NOT set here. The HTTP API's
    cors_configuration (see aws_apigatewayv2_api.dashboard in dashboard.tf) is
    the single source of truth for CORS — it answers preflight OPTIONS requests
    and injects Access-Control-Allow-* on responses. Emitting the same headers
    from the Lambda as well would produce duplicate CORS headers, which browsers
    reject. The allowed origin/methods/headers live in that Terraform config.
    """
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": json.dumps(body),
    }


def handle_stop_query(event):
    """POST /query/stop/{id} — cancel a running query."""
    execution_id = event.get("pathParameters", {}).get("id", "")
    if not execution_id:
        return response_json(400, {"error": "Missing execution ID"})

    try:
        athena.stop_query_execution(QueryExecutionId=execution_id)
        user = get_user_from_event(event)
        logger.info(f"Query stopped by {user}: {execution_id}")
        return response_json(200, {"stopped": execution_id})
    except Exception as e:
        logger.error(f"Failed to stop query: {e}")
        return response_json(500, {"error": "Failed to stop query."})


def handler(event, context):
    """Lambda handler — routes on API Gateway routeKey."""
    route_key = event.get("routeKey", "")
    logger.info(f"Route: {route_key}")

    if route_key == "GET /queries":
        return handle_list_queries(event)
    elif route_key == "POST /query/start":
        return handle_start_query(event)
    elif route_key == "GET /query/status/{id}":
        return handle_query_status(event)
    elif route_key == "GET /query/results/{id}":
        return handle_query_results(event)
    elif route_key == "POST /query/stop/{id}":
        return handle_stop_query(event)
    elif route_key == "POST /query/save":
        return handle_save_query(event)
    elif route_key == "DELETE /query/custom/{id}":
        return handle_delete_custom_query(event)
    elif route_key.startswith("OPTIONS"):
        return response_json(200, {})
    else:
        return response_json(404, {"error": f"Unknown route: {route_key}"})
