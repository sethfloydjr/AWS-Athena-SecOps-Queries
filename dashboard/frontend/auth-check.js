// CloudFront Function: viewer-request auth check
// Validates JWT cookie before serving protected content.
// NOTE: This does structural + claims validation only (exp, iss).
// CloudFront Functions cannot make network calls, so cryptographic
// signature verification against the Okta JWKS is not possible here.
// The API Gateway has its own JWT authorizer that DOES verify signatures.

// Base64 decoder for CloudFront Functions runtime
var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
function b64decode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    var out = '';
    for (var i = 0; i < str.length; i += 4) {
        var a = B64.indexOf(str.charAt(i));
        var b = B64.indexOf(str.charAt(i + 1));
        var c = B64.indexOf(str.charAt(i + 2));
        var d = B64.indexOf(str.charAt(i + 3));
        var bits = (a << 18) | (b << 12) | (c << 6) | d;
        out += String.fromCharCode((bits >> 16) & 0xff);
        if (c !== 64) out += String.fromCharCode((bits >> 8) & 0xff);
        if (d !== 64) out += String.fromCharCode(bits & 0xff);
    }
    return out;
}

// Paths that don't require authentication
var PUBLIC_PATHS = {
    '/': true,
    '/index.html': true,
    '/index.js': true,
    '/robots.txt': true,
    '/.well-known/security.txt': true
};

function handler(event) {
    var request = event.request;
    var uri = request.uri;

    // Allow public paths without auth
    if (PUBLIC_PATHS[uri]) {
        return request;
    }

    // Extract JWT from cookie
    var token = '';
    if (request.cookies && request.cookies['${cookie_name}']) {
        token = request.cookies['${cookie_name}'].value;
    }

    if (!token) {
        return {
            statusCode: 403,
            statusDescription: 'Forbidden',
            headers: { 'content-type': { value: 'text/plain' } },
            body: 'Authentication required. Please sign in.'
        };
    }

    // Validate JWT structure and claims
    try {
        var parts = token.split('.');
        if (parts.length !== 3) throw 'bad jwt';

        var payload = JSON.parse(b64decode(parts[1]));

        // Reject tokens missing exp claim entirely — exp is a critical
        // compensating control since we can't verify signatures
        var now = Math.floor(Date.now() / 1000);
        if (!payload.exp || payload.exp < now) throw 'expired';

        // Check issuer is exactly the Okta org authorization server
        if (payload.iss !== '${okta_issuer_url}') throw 'bad issuer';

    } catch (e) {
        return {
            statusCode: 403,
            statusDescription: 'Forbidden',
            headers: { 'content-type': { value: 'text/plain' } },
            body: 'Authentication required. Please sign in.'
        };
    }

    return request;
}
