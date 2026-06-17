// Athena Security Dashboard — frontend application logic.
//
// Served as a static file from S3/CloudFront. Loaded by dashboard.html via
// <script src="dashboard.js">. No inline scripts or inline event handlers are
// used anywhere, so the page satisfies a strict `script-src 'self'` CSP.
//
// ${API_GATEWAY_URL} is substituted at deploy time by Terraform's replace()
// in dashboard.tf (see the aws_s3_object.dashboard_app_js resource).

// ==================== AUTH CHECK ====================
function checkAuth() {
    const token = localStorage.getItem('access_token');
    const expiry = localStorage.getItem('token_expiry');
    if (!token || (expiry && Date.now() > parseInt(expiry))) {
        localStorage.clear();
        document.cookie = 'athena_token=; path=/; max-age=0; secure; samesite=strict';
        window.location.href = '/';
        return false;
    }
    return true;
}

const API_URL = '${API_GATEWAY_URL}';

// esc() — safe for HTML text content (encodes < > &)
function esc(str) {
    const d = document.createElement('div');
    d.textContent = str || '';
    return d.innerHTML;
}

// escAttr() — safe for inert HTML attribute values (title, value, placeholder,
// id, and data-* attributes read back via element.dataset). All dynamic markup
// is injected as HTML text content (esc) or attribute values (escAttr); nothing
// is interpolated into an inline event handler, so a JS-string encoder is no
// longer needed.
function escAttr(str) {
    return esc(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function getAuthHeaders() { return { 'Authorization': `Bearer ${localStorage.getItem('access_token')}` }; }

function logout() {
    localStorage.clear();
    sessionStorage.clear();
    document.cookie = 'athena_token=; path=/; max-age=0; secure; samesite=strict';
    window.location.href = '/';
}

async function apiCall(path, options = {}) {
    const response = await fetch(`${API_URL}${path}`, {
        ...options, headers: { ...getAuthHeaders(), ...(options.headers || {}) },
    });
    if (response.status === 401) { logout(); return null; }
    return response.json();
}

// ==================== STATE ====================
let allQueries = {};
let selectedQuery = null;
let currentExecutionId = null;
let pollInterval = null;
let searchTerm = '';

const CATEGORY_ORDER = ['Critical Incident Response', 'CloudTrail API Activity', 'Visibility & Data Gaps', 'Compliance & Inventory', 'Diagnostics', 'Other', 'Custom Queries'];

// ==================== SIDEBAR ====================
async function loadQueries() {
    const data = await apiCall('/queries');
    if (!data) return;
    allQueries = data.categories || {};
    renderSidebar();
}

function getAllQueriesFlat() {
    const flat = [];
    for (const [cat, queries] of Object.entries(allQueries)) {
        for (const q of queries) flat.push({ ...q, category: cat });
    }
    return flat;
}

function renderSidebar() {
    const sidebar = document.getElementById('sidebar');
    const term = searchTerm.toLowerCase().trim();
    let html = '<input type="text" class="search-box" placeholder="Search queries..." value="' + escAttr(searchTerm || '') + '">';

    if (term) {
        const matches = getAllQueriesFlat().filter(q =>
            q.name.toLowerCase().includes(term) || (q.description || '').toLowerCase().includes(term)
        );
        if (matches.length === 0) {
            html += '<p style="color:#484f58; padding:12px; font-size:13px;">No queries found.</p>';
        } else {
            for (const q of matches) {
                const active = selectedQuery && selectedQuery.id === q.id ? 'active' : '';
                const deleteBtn = q.isCustom ? `<button class="delete-btn" data-action="delete" data-id="${escAttr(q.id)}" title="Delete">&times;</button>` : '';
                html += `<div class="query-item ${active}" data-action="select" data-id="${escAttr(q.id)}"><span>${esc(q.name)}<span class="search-cat-label">${esc(q.category)}</span></span>${deleteBtn}</div>`;
            }
        }
    } else {
        for (const cat of CATEGORY_ORDER) {
            if (!allQueries[cat]) continue;
            if (cat === 'Custom Queries') {
                html += `<h2>${cat} <span class="query-count">(${allQueries[cat].length})</span> <a class="guide-link" data-action="guide">? Guide</a></h2>`;
                html += `<div class="query-item" data-action="new" style="color:#3fb950;">+ New Query</div>`;
            } else {
                html += `<h2>${cat} <span class="query-count">(${allQueries[cat].length})</span></h2>`;
            }
            for (const q of allQueries[cat]) {
                const active = selectedQuery && selectedQuery.id === q.id ? 'active' : '';
                const deleteBtn = q.isCustom ? `<button class="delete-btn" data-action="delete" data-id="${escAttr(q.id)}" title="Delete">&times;</button>` : '';
                html += `<div class="query-item ${active}" data-action="select" data-id="${escAttr(q.id)}"><span>${esc(q.name)}</span>${deleteBtn}</div>`;
            }
        }
        if (!allQueries['Custom Queries']) {
            html += `<h2>Custom Queries <span class="query-count">(0)</span> <a class="guide-link" data-action="guide">? Guide</a></h2>`;
        }
        html += `<div class="query-item" data-action="new" style="color:#3fb950;">+ New Query</div>`;
    }
    sidebar.innerHTML = html;
}

function onSearch(value) { searchTerm = value; renderSidebar(); }

function findQuery(id) {
    for (const cat of Object.values(allQueries)) {
        for (const q of cat) { if (q.id === id) return q; }
    }
    return null;
}

function selectQuery(id) {
    stopPolling();
    selectedQuery = findQuery(id);
    if (!selectedQuery) return;
    renderSidebar();
    renderQueryPanel();
}

// Delegated sidebar events. The sidebar markup is rebuilt via innerHTML, so
// listeners are attached once to the stable #sidebar parent and dispatch on the
// nearest [data-action] ancestor of the clicked node.
function initSidebarEvents() {
    const sidebar = document.getElementById('sidebar');
    sidebar.addEventListener('click', (e) => {
        const el = e.target.closest('[data-action]');
        if (!el || !sidebar.contains(el)) return;
        switch (el.dataset.action) {
            case 'select': selectQuery(el.dataset.id); break;
            case 'delete': deleteCustomQuery(el.dataset.id); break;
            case 'guide': showGuide(); break;
            case 'new': newQuery(); break;
        }
    });
    sidebar.addEventListener('input', (e) => {
        if (e.target.classList.contains('search-box')) onSearch(e.target.value);
    });
}

// ==================== QUERY PANEL ====================
function renderQueryPanel() {
    const q = selectedQuery;
    const content = document.getElementById('content');
    let paramsHtml = '';
    if (q.parameters && q.parameters.length > 0) {
        paramsHtml = '<div class="params">';
        for (const p of q.parameters) {
            paramsHtml += `<div class="param-row"><label>${esc(p.label)}</label><input type="text" id="param-${escAttr(p.name)}" placeholder="${escAttr(p.name)}" data-action="update-param" data-param="${escAttr(p.name)}"></div>`;
        }
        paramsHtml += '</div>';
    }
    content.innerHTML = `
        <div class="query-name">${esc(q.name)}${q.isCustom ? ' <span style="color:#8b949e;font-size:12px;">(custom)</span>' : ''}</div>
        <div class="query-desc">${esc(q.description || '')}</div>
        ${paramsHtml}
        <textarea class="sql-editor" id="sql-editor">${esc(q.sql)}</textarea>
        <div class="controls">
            <button class="btn btn-run" id="btn-run" data-action="run">Run Query</button>
            <button class="btn btn-stop" id="btn-stop" data-action="stop" style="display:none;">Stop</button>
            <button class="btn btn-save" data-action="save-modal">Save as Custom Query</button>
            <div class="status" id="status"></div>
        </div>
        <div class="results-container" id="results"></div>
    `;
}

function updateSqlParam(paramName, value) {
    const editor = document.getElementById('sql-editor');
    if (!editor) return;
    const regex = new RegExp(paramName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
    editor.value = editor.value.replace(regex, value || paramName);
}

// Delegated events for the main content panel (query panel + results), both of
// which are rebuilt via innerHTML on the stable #content parent.
function initContentEvents() {
    const content = document.getElementById('content');
    content.addEventListener('click', (e) => {
        const el = e.target.closest('[data-action]');
        if (!el || !content.contains(el)) return;
        switch (el.dataset.action) {
            case 'run': runQuery(); break;
            case 'stop': stopQuery(); break;
            case 'save-modal': showSaveModal(); break;
            case 'load-more': loadResults(el.dataset.token); break;
            case 'download-csv': downloadCsv(); break;
        }
    });
    content.addEventListener('change', (e) => {
        const el = e.target.closest('[data-action="update-param"]');
        if (!el) return;
        updateSqlParam(el.dataset.param, el.value);
    });
}

// ==================== QUERY EXECUTION ====================
async function runQuery() {
    const sql = document.getElementById('sql-editor').value.trim();
    if (!sql) return;
    document.getElementById('btn-run').disabled = true;
    document.getElementById('btn-stop').style.display = '';
    document.getElementById('status').innerHTML = '<div class="spinner"></div> <span class="status-badge status-running">RUNNING</span>';
    document.getElementById('results').innerHTML = '';
    const data = await apiCall('/query/start', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql: sql, database: selectedQuery?.database || '' }),
    });
    if (!data || data.error) {
        document.getElementById('status').innerHTML = `<span class="status-badge status-failed">ERROR</span> <span class="stats">${esc(data?.error || 'Failed')}</span>`;
        document.getElementById('btn-run').disabled = false;
        document.getElementById('btn-stop').style.display = 'none';
        return;
    }
    currentExecutionId = encodeURIComponent(data.executionId);
    startPolling();
}

function startPolling() {
    pollInterval = setInterval(async () => {
        const data = await apiCall(`/query/status/${currentExecutionId}`);
        if (!data) { stopPolling(); return; }
        const mb = (data.bytesScanned / 1024 / 1024).toFixed(2);
        if (data.state === 'SUCCEEDED') {
            stopPolling();
            document.getElementById('status').innerHTML = `<span class="status-badge status-succeeded">SUCCEEDED</span> <span class="stats">${esc(mb)} MB scanned | ${esc(String(data.executionTimeMs))}ms</span>`;
            loadResults();
        } else if (data.state === 'FAILED' || data.state === 'CANCELLED') {
            stopPolling();
            document.getElementById('status').innerHTML = `<span class="status-badge status-failed">${esc(data.state)}</span> <span class="stats">${esc(data.stateChangeReason || '')}</span>`;
        } else {
            document.getElementById('status').innerHTML = `<div class="spinner"></div> <span class="status-badge status-running">${esc(data.state)}</span> <span class="stats">${esc(mb)} MB scanned</span>`;
        }
    }, 2000);
}

function stopPolling() {
    if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
    const btnRun = document.getElementById('btn-run');
    const btnStop = document.getElementById('btn-stop');
    if (btnRun) btnRun.disabled = false;
    if (btnStop) btnStop.style.display = 'none';
}

async function stopQuery() {
    if (!currentExecutionId) return;
    await apiCall(`/query/stop/${currentExecutionId}`, { method: 'POST' });
    stopPolling();
    document.getElementById('status').innerHTML = '<span class="status-badge status-failed">CANCELLED</span>';
}

async function loadResults(nextToken) {
    const params = nextToken ? `?nextToken=${encodeURIComponent(nextToken)}` : '';
    const data = await apiCall(`/query/results/${currentExecutionId}${params}`);
    if (!data || data.error) {
        document.getElementById('results').innerHTML = `<p style="color:#f85149;">Error: ${esc(data?.error || 'Unknown')}</p>`;
        return;
    }
    let html = '<table><thead><tr>';
    for (const col of data.columns) html += `<th>${esc(col)}</th>`;
    html += '</tr></thead><tbody>';
    for (const row of data.rows) {
        html += '<tr>';
        for (const col of data.columns) html += `<td title="${escAttr(row[col] || '')}">${esc(row[col] || '')}</td>`;
        html += '</tr>';
    }
    html += '</tbody></table><div class="pagination">';
    html += `<span class="row-count">${data.rowCount} rows</span>`;
    if (data.nextToken) html += `<button class="btn btn-csv" data-action="load-more" data-token="${escAttr(data.nextToken)}">Load More</button>`;
    html += `<button class="btn btn-csv" data-action="download-csv">Download CSV</button></div>`;
    document.getElementById('results').innerHTML = html;
}

// csvCell() — quote a value for CSV and neutralize spreadsheet formula
// injection. A cell beginning with = + - @ (or a tab/CR that a spreadsheet
// trims back to one of those) is treated as a formula by Excel/Sheets, so
// query data like "=cmd|..." could execute on open. Prefix those with a
// single quote so they import as inert text.
function csvCell(value) {
    let s = (value == null) ? '' : String(value);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
}

function downloadCsv() {
    const table = document.querySelector('#results table');
    if (!table) return;
    let csv = '';
    for (const row of table.rows) {
        csv += Array.from(row.cells).map(c => csvCell(c.textContent)).join(',') + '\n';
    }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `${(selectedQuery?.name || 'query').replace(/[^a-zA-Z0-9_-]/g, '_')}-results.csv`;
    a.click();
}

// ==================== NEW QUERY FROM TEMPLATE ====================
function newQuery() {
    stopPolling();
    selectedQuery = {
        id: null,
        name: 'New Custom Query',
        description: 'Write your query below. Choose either the CloudTrail or Config template, delete the one you don\'t need, and uncomment the one you want to use.',
        sql: `-- =====================================================
-- CHOOSE ONE TEMPLATE BELOW
-- Delete the one you don't need, uncomment the other
-- =====================================================


-- =====================================================
-- OPTION 1: CLOUDTRAIL TEMPLATE
-- Use this when you need to answer: Who did what? When? From where?
-- Examples: console logins, IAM changes, API calls, security group mods
-- Date format is ZERO-PADDED: '2026/07/01'
-- =====================================================

-- SELECT
--     eventtime,
--     eventname,
--     useridentity.arn AS principal,
--     sourceipaddress,
--     awsregion,
--     requestparameters,
--     responseelements,
--     errorcode
-- FROM security_incident_response.cloudtrail_logs
-- WHERE accountid = '123456789012'
--     AND region = 'us-east-1'
--     AND dt BETWEEN '2026/07/01' AND '2026/07/07'
--     AND eventname = 'REPLACE_WITH_EVENT_NAME'
-- ORDER BY eventtime DESC


-- =====================================================
-- OPTION 2: CONFIG TEMPLATE
-- Use this when you need to answer: What does a resource look like?
-- Examples: IAM users, security groups, S3 settings, EC2 inventory
-- Date format is NON-PADDED: '2026/7/1'
-- S3 and IAM are global — always use region = 'us-east-1'
-- =====================================================

-- SELECT
--     ci.awsaccountid AS account_id,
--     ci.awsregion AS aws_region,
--     ci.resourcetype,
--     ci.resourceid,
--     ci.resourcename,
--     ci.configuration,
--     ci.tags
-- FROM security_incident_response.config_snapshots
-- CROSS JOIN UNNEST(configurationitems) AS t(ci)
-- WHERE ci.resourcetype = 'AWS::EC2::Instance'
--     AND ci.configurationitemstatus = 'OK'
--     AND accountid = '123456789012'
--     AND region = 'us-east-1'
--     AND dt = '2026/7/1'
-- ORDER BY ci.awsaccountid, ci.resourceid`,
        database: 'security_incident_response',
        parameters: [],
        isCustom: true,
    };
    renderSidebar();
    renderQueryPanel();
}

// ==================== CUSTOM QUERY SAVE/DELETE ====================
function showSaveModal() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'save-modal';
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
    overlay.innerHTML = `
        <div class="modal">
            <h3>Save Custom Query</h3>
            <label>Name (will be prefixed with custom_)</label>
            <input type="text" id="save-name" placeholder="my_query_name">
            <label>Description</label>
            <textarea id="save-desc" placeholder="What this query does and what to look for in the results"></textarea>
            <div class="warning">&#9888;&#65039; Reminder: Always include partition filters (accountid, region, dt) in custom queries to avoid scanning excess data and hitting the 200GB limit.</div>
            <div class="modal-buttons">
                <button class="btn btn-cancel" data-action="cancel">Cancel</button>
                <button class="btn btn-save" data-action="save-query">Save</button>
            </div>
        </div>
    `;
    overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => overlay.remove());
    overlay.querySelector('[data-action="save-query"]').addEventListener('click', saveCustomQuery);
    document.body.appendChild(overlay);
}

async function saveCustomQuery() {
    const name = document.getElementById('save-name').value.trim();
    const desc = document.getElementById('save-desc').value.trim();
    const sql = document.getElementById('sql-editor')?.value?.trim() || '';
    if (!name) { alert('Name is required'); return; }
    if (!desc) { alert('Description is required'); return; }
    if (!sql) { alert('No SQL to save'); return; }
    const data = await apiCall('/query/save', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, description: desc, sql: sql }),
    });
    if (data && !data.error) {
        document.getElementById('save-modal').remove();
        await loadQueries();
    } else {
        alert('Failed to save: ' + (data?.error || 'Unknown error'));
    }
}

async function deleteCustomQuery(id) {
    if (!confirm('Delete this custom query?')) return;
    const data = await apiCall(`/query/custom/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (data && !data.error) {
        if (selectedQuery && selectedQuery.id === id) {
            selectedQuery = null;
            document.getElementById('content').innerHTML = '<div class="empty-state"><h2>Select a query</h2><p>Choose a query from the sidebar to get started</p></div>';
        }
        await loadQueries();
    } else {
        alert('Failed to delete: ' + (data?.error || 'Unknown error'));
    }
}

// ==================== USER GUIDE ====================
function showGuide() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'guide-modal';
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
    overlay.innerHTML = `
        <div class="guide-modal">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h2 style="margin:0;">How to Write a Custom Query</h2>
                <button class="delete-btn" style="font-size:24px;" data-action="close-guide">&times;</button>
            </div>
            <h3>Step 1: Choose the Right Data Source</h3>
            <p><strong>Use <code>cloudtrail_logs</code></strong> when you need to answer:</p>
            <ul><li>Who did something?</li><li>When did it happen?</li><li>Where did it come from?</li></ul>
            <p>Examples: console logins, IAM changes, S3 policy modifications, API calls</p>
            <p><strong>Use <code>config_snapshots</code></strong> when you need to answer:</p>
            <ul><li>What does a resource look like right now?</li><li>What is configured across my accounts?</li></ul>
            <p>Examples: IAM users, security group rules, S3 bucket settings, EC2 inventory</p>
            <hr>
            <h3>Step 2: Always Start With Partition Filters</h3>
            <p>&#9888;&#65039; <strong>This is the most important rule.</strong> Without partition filters, Athena scans the entire dataset. This is slow, expensive, and will hit the 200GB limit.</p>
            <table><tr><th>Column</th><th>Example</th><th>Notes</th></tr>
            <tr><td><code>accountid</code></td><td><code>accountid = '123456789012'</code></td><td>See account list below</td></tr>
            <tr><td><code>region</code></td><td><code>region = 'us-east-1'</code></td><td>S3 and IAM: always us-east-1</td></tr>
            <tr><td><code>dt</code></td><td><code>dt = '2026/07/01'</code></td><td>CloudTrail: zero-padded. Config: non-padded</td></tr></table>
            <p><strong>CloudTrail:</strong> <code>'2026/07/01'</code> &nbsp; <strong>Config:</strong> <code>'2026/7/1'</code></p>
            <hr>
            <h3>Step 3: Use the Right Query Pattern</h3>
            <p><strong>CloudTrail Pattern</strong></p>
            <pre><code>SELECT eventtime, eventname, useridentity.arn, sourceipaddress
FROM security_incident_response.cloudtrail_logs
WHERE accountid = '123456789012'
  AND region = 'us-east-1'
  AND dt BETWEEN '2026/07/01' AND '2026/07/07'
  AND eventname = 'ConsoleLogin'
ORDER BY eventtime DESC</code></pre>
            <p><strong>Config Pattern</strong></p>
            <pre><code>SELECT ci.awsaccountid AS account_id, ci.resourcename, ci.configuration
FROM security_incident_response.config_snapshots
CROSS JOIN UNNEST(configurationitems) AS t(ci)
WHERE accountid = '123456789012'
  AND region = 'us-east-1'
  AND dt = '2026/7/1'
  AND ci.resourcetype = 'AWS::EC2::SecurityGroup'</code></pre>
            <hr>
            <h3>Step 4: Extracting JSON Fields</h3>
            <p><strong>Single value:</strong></p>
            <pre><code>json_extract_scalar(ci.configuration, '$.publicIpAddress')</code></pre>
            <p><strong>Nested object:</strong></p>
            <pre><code>json_extract(ci.configuration, '$.ipPermissions')</code></pre>
            <p><strong>CloudTrail nested fields:</strong></p>
            <pre><code>useridentity.arn
useridentity.username
useridentity.accesskeyid
useridentity.sessioncontext.sessionissuer.arn</code></pre>
            <p><strong>Config supplementary configuration:</strong></p>
            <pre><code>element_at(ci.supplementaryconfiguration, 'PublicAccessBlockConfiguration')
element_at(ci.supplementaryconfiguration, 'BucketLoggingConfiguration')</code></pre>
            <hr>
            <h3>Worked Example: Console Logins Outside Business Hours</h3>
            <pre><code>SELECT eventtime, useridentity.arn, sourceipaddress,
  json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa_used
FROM security_incident_response.cloudtrail_logs
WHERE accountid = '123456789012'
  AND region = 'us-east-1'
  AND dt BETWEEN '2026/07/01' AND '2026/07/07'
  AND eventname = 'ConsoleLogin'
  AND HOUR(PARSE_DATETIME(eventtime, 'yyyy-MM-dd''T''HH:mm:ss''Z''')) BETWEEN 0 AND 5
ORDER BY eventtime DESC</code></pre>
            <hr>
            <h3>Known Limitations</h3>
            <ul>
                <li><strong>Config data is not real-time.</strong> Snapshots every 3-12 hours.</li>
                <li><strong>CloudTrail does not log S3 object-level access</strong> unless data events are enabled.</li>
                <li><strong>s3_buckets_public checks ACLs only</strong> — not bucket policies. Use S3 Access Analyzer.</li>
                <li><strong>S3 and IAM are global.</strong> Always use <code>region = 'us-east-1'</code>.</li>
            </ul>
            <hr>
            <h3>AWS Account IDs</h3>
            <table><tr><th>Account</th><th>ID</th></tr>
            <tr><td>Prod</td><td>111111111104</td></tr><tr><td>Stage</td><td>111111111103</td></tr>
            <tr><td>Dev</td><td>111111111102</td></tr><tr><td>QA</td><td>111111111107</td></tr>
            <tr><td>Security</td><td>111111111105</td></tr><tr><td>Tooling</td><td>111111111109</td></tr>
            <tr><td>Sandbox</td><td>111111111106</td></tr><tr><td>DataScience</td><td>111111111110</td></tr>
            <tr><td>Root</td><td>111111111108</td></tr><tr><td>App</td><td>111111111101</td></tr>
            <tr><td>Interconnect</td><td>111111111113</td></tr><tr><td>Carrier Interconnect</td><td>111111111114</td></tr>
            <tr><td>Carrier Prod US-East-1</td><td>111111111115</td></tr><tr><td>Carrier Prod US-West-2</td><td>111111111116</td></tr>
            <tr><td>Carrier Lab US-East-1</td><td>111111111117</td></tr><tr><td>Backend Test</td><td>111111111111</td></tr>
            <tr><td>Client Test</td><td>111111111112</td></tr></table>
        </div>
    `;
    overlay.querySelector('[data-action="close-guide"]').addEventListener('click', () => overlay.remove());
    document.body.appendChild(overlay);
}

// ==================== INIT ====================
function init() {
    if (!checkAuth()) return;
    document.getElementById('logout-link').addEventListener('click', logout);
    initSidebarEvents();
    initContentEvents();
    document.getElementById('user-email').textContent = localStorage.getItem('user_email') || '';
    loadQueries();
}

init();
