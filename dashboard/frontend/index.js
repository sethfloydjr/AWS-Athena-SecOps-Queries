// Athena Security Dashboard — login page logic (Okta OIDC, PKCE).
//
// Served as a static file from S3/CloudFront and loaded by index.html via
// <script src="index.js">. No inline scripts or inline event handlers are used,
// so the page satisfies a strict `script-src 'self'` CSP. This file is part of
// the unauthenticated login flow, so it is listed in PUBLIC_PATHS in
// auth-check.js (the CloudFront viewer-request auth gate).

const OKTA_ISSUER = 'https://example.okta.com';
const OKTA_CLIENT_ID = '0oaEXAMPLECLIENTID00';
const REDIRECT_URI = 'https://company-athena-dashboard.security.example.com';

function generateRandomString(length) {
    const arr = new Uint8Array(length);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('').slice(0, length);
}

async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(digest)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function login() {
    const state = generateRandomString(32);
    const codeVerifier = generateRandomString(64);
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    sessionStorage.setItem('pkce_state', state);
    sessionStorage.setItem('pkce_code_verifier', codeVerifier);
    const params = new URLSearchParams({
        client_id: OKTA_CLIENT_ID, response_type: 'code', scope: 'openid email profile',
        redirect_uri: REDIRECT_URI, state: state, code_challenge: codeChallenge, code_challenge_method: 'S256',
    });
    window.location.href = `${OKTA_ISSUER}/oauth2/v1/authorize?${params}`;
}

async function handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    if (!code) return false;
    if (state !== sessionStorage.getItem('pkce_state')) {
        document.getElementById('error').textContent = 'Authentication error: state mismatch. Please try again.';
        return false;
    }
    const tokenResponse = await fetch(`${OKTA_ISSUER}/oauth2/v1/token`, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code', client_id: OKTA_CLIENT_ID,
            code: code, redirect_uri: REDIRECT_URI, code_verifier: sessionStorage.getItem('pkce_code_verifier'),
        }),
    });
    if (!tokenResponse.ok) {
        document.getElementById('error').textContent = 'Token exchange failed. Please try again.';
        return false;
    }
    const tokens = await tokenResponse.json();
    if (!tokens.id_token) {
        document.getElementById('error').textContent = 'Authentication failed: no token received.';
        return false;
    }
    localStorage.setItem('access_token', tokens.id_token);
    localStorage.setItem('id_token', tokens.id_token);
    if (tokens.expires_in) localStorage.setItem('token_expiry', Date.now() + tokens.expires_in * 1000);
    // Set auth cookie for CloudFront Function to validate on protected paths
    const maxAge = tokens.expires_in || 3600;
    document.cookie = `athena_token=${tokens.id_token}; path=/; max-age=${maxAge}; secure; samesite=strict`;
    try {
        // JWT uses base64url encoding — convert to standard base64 before decoding
        const b64url = tokens.id_token.split('.')[1];
        const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
        const payload = JSON.parse(atob(b64));
        localStorage.setItem('user_email', payload.email || payload.sub || 'Unknown');
    } catch (e) {}
    return true;
}

async function init() {
    document.getElementById('login-btn').addEventListener('click', login);
    if (window.location.search.includes('code=')) {
        const success = await handleCallback();
        if (success) {
            window.location.href = '/dashboard.html';
            return;
        }
    }
    // Already authenticated — go straight to dashboard
    const token = localStorage.getItem('access_token');
    const expiry = localStorage.getItem('token_expiry');
    if (token && (!expiry || Date.now() < parseInt(expiry))) {
        window.location.href = '/dashboard.html';
    }
}

init();
