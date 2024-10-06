import { nanoid } from 'nanoid';
import { authenticator } from 'otplib';
import jwt from '@tsndr/cloudflare-worker-jwt';

// 辅助函数
const jsonResponse = (data, status = 200, additionalHeaders = {}) => {
    const headers = {
        'Content-Type': 'application/json',
        ...additionalHeaders,
    };
    return new Response(JSON.stringify(data), { status, headers });
};

function handleCors() {
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Credentials': 'true',
    };
}

const handleErrors = async (request, func) => {
    try {
        return await func();
    } catch (error) {
        console.error('Error details:', error);
        console.error('Error stack:', error.stack);
        return jsonResponse({ error: error.message }, 500);
    }
};

// TOTP 相关函数
async function handleGetTOTPs(env) {
    const totps = await env.TOTP_STORE.list();
    const totpList = [];
    for (const key of totps.keys) {
        if (key.name !== 'github_state' && key.name !== 'github_token' && key.name !== 'gist_id') {
            try {
                const totpData = await env.TOTP_STORE.get(key.name);
                console.log(`Raw TOTP data for ${key.name}:`, totpData);
                if (totpData) {
                    const parsedData = JSON.parse(totpData);
                    totpList.push(parsedData);
                }
            } catch (error) {
                console.error(`Error parsing TOTP data for ${key.name}:`, error);
            }
        }
    }
    return totpList;
}

async function handleAddTOTP(request, env) {
    const { userInfo, secret } = await request.json();
    if (!userInfo || !secret) {
        return jsonResponse({ error: 'User info and secret are required' }, 400);
    }
    const id = nanoid();
    const totp = { id, userInfo, secret, createdAt: new Date().toISOString() };
    await env.TOTP_STORE.put(id, JSON.stringify(totp));
    return totp;
}

async function handleDeleteTOTP(request, env) {
    const url = new URL(request.url);
    const id = url.pathname.split('/').pop();
    await env.TOTP_STORE.delete(id);
    return { message: 'TOTP deleted successfully' };
}

async function handleGenerateToken(request, env) {
    const url = new URL(request.url);
    const id = url.pathname.split('/').slice(-2)[0];
    console.log('Generating token for ID:', id);
    const totpData = await env.TOTP_STORE.get(id);
    if (!totpData) {
        console.error('TOTP not found for ID:', id);
        return jsonResponse({ error: 'TOTP not found' }, 404);
    }
    try {
        const totp = JSON.parse(totpData);
        const token = authenticator.generate(totp.secret);
        return { token };
    } catch (error) {
        console.error('Error generating token:', error);
        return jsonResponse({ error: 'Failed to generate token' }, 500);
    }
}

async function handleExportTOTP(request, env) {
    const url = new URL(request.url);
    const id = url.pathname.split('/').slice(-2)[0];
    console.log('Exporting TOTP for ID:', id);
    const totpData = await env.TOTP_STORE.get(id);
    if (!totpData) {
        console.error('TOTP not found for ID:', id);
        return jsonResponse({ error: 'TOTP not found' }, 404);
    }
    try {
        const totp = JSON.parse(totpData);
        const uri = authenticator.keyuri(totp.userInfo, 'TOTP Manager', totp.secret);
        return { uri };
    } catch (error) {
        console.error('Error exporting TOTP:', error);
        return jsonResponse({ error: 'Failed to export TOTP' }, 500);
    }
}

async function handleClearAllTOTPs(env) {
    const totps = await env.TOTP_STORE.list();
    for (const key of totps.keys) {
        if (key.name !== 'github_token' && key.name !== 'github_state' && key.name !== 'gist_id') {
            await env.TOTP_STORE.delete(key.name);
        }
    }
    return { message: 'All TOTPs cleared successfully' };
}

async function handleImportTOTP(request, env) {
    const { qrData } = await request.json();
    console.log('Importing TOTP with data:', qrData);
    try {
        let totps = [];
        if (qrData.startsWith('otpauth-migration://offline?data=')) {
            const base64Data = qrData.split('data=')[1];
            const decodedData = atob(decodeURIComponent(base64Data));
            const binaryData = new Uint8Array(decodedData.length);
            for (let i = 0; i < decodedData.length; i++) {
                binaryData[i] = decodedData.charCodeAt(i);
            }
            totps = parseOtpMigrationData(binaryData);
        } else if (qrData.startsWith('otpauth://')) {
            const uri = new URL(qrData);
            const secret = uri.searchParams.get('secret');
            const userInfo = decodeURIComponent(uri.pathname.split('/').pop());

            if (!secret || !userInfo) {
                console.error('Invalid QR code data:', { secret, userInfo });
                return jsonResponse({ error: 'Invalid QR code data' }, 400);
            }

            totps = [{ userInfo, secret }];
        } else {
            return jsonResponse({ error: 'Unsupported QR code format' }, 400);
        }

        if (!Array.isArray(totps) || totps.length === 0) {
            return jsonResponse({ error: 'No valid TOTP entries found' }, 400);
        }

        for (const totp of totps) {
            const id = nanoid();
            await env.TOTP_STORE.put(id, JSON.stringify({
                id,
                userInfo: totp.userInfo,
                secret: totp.secret,
                createdAt: new Date().toISOString()
            }));
        }

        console.log('TOTPs imported successfully:', totps.length);
        return { success: true, count: totps.length };
    } catch (error) {
        console.error('Import TOTP error:', error);
        return jsonResponse({ error: 'Failed to import TOTP: ' + error.message }, 400);
    }
}

function parseOtpMigrationData(binaryData) {
    let index = 0;
    const totps = [];

    while (index < binaryData.length) {
        if (index + 1 >= binaryData.length) break;

        const fieldNumber = binaryData[index] >> 3;
        const wireType = binaryData[index] & 0x07;
        index++;

        switch (wireType) {
            case 0: // Varint
                const [_, bytesRead] = decodeVarint(binaryData.slice(index));
                index += bytesRead;
                break;
            case 2: // Length-delimited
                const [length, lengthBytesRead] = decodeVarint(binaryData.slice(index));
                index += lengthBytesRead;
                if (index + length > binaryData.length) {
                    throw new Error("Invalid length-delimited field length");
                }
                const fieldData = binaryData.slice(index, index + length);
                index += length;

                if (fieldNumber === 1) {
                    const totp = parseTOTPEntry(fieldData);
                    if (totp) totps.push(totp);
                }
                break;
            default:
                // Skip unknown wire types
                index++;
                break;
        }
    }

    if (totps.length === 0) {
        console.warn("No valid TOTP entries found in migration data");
    }

    return totps;
}

function parseTOTPEntry(data) {
    let index = 0;
    let secret = '';
    let name = '';
    let issuer = '';

    while (index < data.length) {
        if (index + 1 >= data.length) break;

        const fieldNumber = data[index] >> 3;
        const wireType = data[index] & 0x07;
        index++;

        switch (wireType) {
            case 0: // Varint
                const [_, bytesRead] = decodeVarint(data.slice(index));
                index += bytesRead;
                break;
            case 2: // Length-delimited
                const [length, lengthBytesRead] = decodeVarint(data.slice(index));
                index += lengthBytesRead;
                if (index + length > data.length) {
                    throw new Error("Invalid length-delimited field length");
                }
                const fieldData = data.slice(index, index + length);
                index += length;

                switch (fieldNumber) {
                    case 1: // Secret
                        secret = base32Encode(fieldData);
                        break;
                    case 2: // Name
                        name = utf8Decode(fieldData);
                        break;
                    case 3: // Issuer
                        issuer = utf8Decode(fieldData);
                        break;
                }
                break;
            default:
                // Skip unknown wire types
                index++;
                break;
        }
    }

    if (secret && name) {
        const userInfo = issuer ? `${name} (${issuer})` : name;
        return { userInfo, secret };
    }

    return null;
}

function decodeVarint(buffer) {
    let result = 0;
    let shift = 0;
    let bytesRead = 0;

    for (const byte of buffer) {
        bytesRead++;
        result |= (byte & 0x7F) << shift;
        if ((byte & 0x80) === 0) break;
        shift += 7;
    }

    return [result, bytesRead];
}

function base32Encode(buffer) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let result = '';
    let bits = 0;
    let value = 0;

    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            result += alphabet[value >>> bits & 31];
        }
    }

    if (bits > 0) {
        result += alphabet[value << (5 - bits) & 31];
    }

    return result;
}

function utf8Decode(buffer) {
    let result = '';
    let i = 0;
    while (i < buffer.length) {
        let c = buffer[i++];
        if (c > 127) {
            if (c > 191 && c < 224) {
                if (i >= buffer.length) throw new Error('UTF-8 decode: incomplete 2-byte sequence');
                c = (c & 31) << 6 | buffer[i++] & 63;
            } else if (c > 223 && c < 240) {
                if (i + 1 >= buffer.length) throw new Error('UTF-8 decode: incomplete 3-byte sequence');
                c = (c & 15) << 12 | (buffer[i++] & 63) << 6 | buffer[i++] & 63;
            } else if (c > 239 && c < 248) {
                if (i + 2 >= buffer.length) throw new Error('UTF-8 decode: incomplete 4-byte sequence');
                c = (c & 7) << 18 | (buffer[i++] & 63) << 12 | (buffer[i++] & 63) << 6 | buffer[i++] & 63;
            } else throw new Error('UTF-8 decode: unknown multibyte start 0x' + c.toString(16) + ' at index ' + (i - 1));
        }
        if (c <= 0xffff) result += String.fromCharCode(c);
        else if (c <= 0x10ffff) {
            c -= 0x10000;
            result += String.fromCharCode(c >> 10 | 0xd800)
            result += String.fromCharCode(c & 0x3FF | 0xdc00)
        } else throw new Error('UTF-8 decode: code point 0x' + c.toString(16) + ' exceeds UTF-16 reach');
    }
    return result;
}

async function handleCleanupKV(env) {
    const totps = await env.TOTP_STORE.list();
    let cleanedCount = 0;
    for (const key of totps.keys) {
        const value = await env.TOTP_STORE.get(key.name);
        try {
            JSON.parse(value);
        } catch (error) {
            console.log(`Deleting invalid entry: ${key.name}`);
            await env.TOTP_STORE.delete(key.name);
            cleanedCount++;
        }
    }
    return { message: `KV cleanup completed. Removed ${cleanedCount} invalid entries.` };
}

// GitHub 相关函数
async function handleGitHubAuthStatus(env) {
    const token = await env.TOTP_STORE.get('github_token');
    return { authenticated: !!token };
}

async function handleGitHubAuth(request, env) {
    const clientId = env.GITHUB_CLIENT_ID;
    const redirectUri = env.GITHUB_REDIRECT_URI;
    const state = nanoid();
    await env.TOTP_STORE.put('github_state', state, { expirationTtl: 600 }); // 10 minutes expiration
    const authUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}&scope=gist`;
    return new Response(null, {
        status: 302,
        headers: {
            'Location': authUrl,
            ...handleCors()
        }
    });
}

async function handleGitHubCallback(request, env) {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    const savedState = await env.TOTP_STORE.get('github_state');
    if (state !== savedState) {
        return new Response(JSON.stringify({ error: 'Invalid state' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...handleCors() }
        });
    }

    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify({
            client_id: env.GITHUB_CLIENT_ID,
            client_secret: env.GITHUB_CLIENT_SECRET,
            code: code
        })
    });

    const tokenData = await tokenResponse.json();
    if (tokenData.access_token) {
        console.log('Received GitHub token:', tokenData.access_token);
        await env.TOTP_STORE.put('github_token', tokenData.access_token);
        return new Response(null, {
            status: 302,
            headers: {
                'Location': env.FRONTEND_URL,
                ...handleCors()
            }
        });
    } else {
        console.error('Failed to obtain GitHub access token:', tokenData);
        return new Response(JSON.stringify({ error: 'Failed to obtain access token' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...handleCors() }
        });
    }
}

async function handleGitHubUpload(request, env) {
    let mode;
    try {
        const body = await request.json();
        mode = body.mode;
    } catch (error) {
        console.error('Error parsing request body:', error);
        return { error: 'Invalid request body' };
    }

    const token = await env.TOTP_STORE.get('github_token');
    if (!token) {
        return { error: 'Not authenticated with GitHub' };
    }

    const totps = await handleGetTOTPs(env);
    const content = JSON.stringify(totps);

    let gistId = await env.TOTP_STORE.get('gist_id');
    let method, url, body;

    if (mode === 'create' || !gistId) {
        method = 'POST';
        url = 'https://api.github.com/gists';
        body = JSON.stringify({
            description: 'TOTP Backup',
            public: false,
            files: {
                'totp_backup.json': {
                    content: content
                }
            }
        });
    } else {
        method = 'PATCH';
        url = `https://api.github.com/gists/${gistId}`;
        body = JSON.stringify({
            description: 'TOTP Backup', // 确保更新时也设置描述
            files: {
                'totp_backup.json': {
                    content: content
                }
            }
        });
    }

    try {
        const response = await fetch(url, {
            method: method,
            headers: {
                'Authorization': `token ${token}`,
                'Content-Type': 'application/json',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
            },
            body: body
        });

        if (!response.ok) {
            const errorBody = await response.text();
            console.error(`GitHub API error: ${response.status} ${response.statusText}`);
            console.error(`Error body: ${errorBody}`);
            throw new Error(`GitHub API responded with status ${response.status}: ${errorBody}`);
        }

        const data = await response.json();
        if (data.id) {
            await env.TOTP_STORE.put('gist_id', data.id);
            return { message: 'Data uploaded to Gist successfully', gistId: data.id };
        } else {
            return { error: 'Failed to upload data to Gist', details: data };
        }
    } catch (error) {
        console.error('Error uploading to GitHub:', error);
        return { error: 'Failed to upload data to Gist', details: error.message };
    }
}

async function handleGitHubVersions(env) {
    const token = await env.TOTP_STORE.get('github_token');
    const gistId = await env.TOTP_STORE.get('gist_id');
    if (!token || !gistId) {
        console.error('GitHub token or gist ID not found');
        return { error: 'Not authenticated with GitHub or no backup found' };
    }

    try {
        console.log(`Fetching versions for gist: ${gistId}`);
        const response = await fetch(`https://api.github.com/gists/${gistId}`, {
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
            }
        });

        if (!response.ok) {
            const errorBody = await response.text();
            console.error(`GitHub API error: ${response.status} ${response.statusText}`);
            console.error(`Error body: ${errorBody}`);
            throw new Error(`GitHub API responded with status ${response.status}: ${errorBody}`);
        }

        const gistData = await response.json();
        console.log('Gist data received:', JSON.stringify(gistData, null, 2));

        const history = gistData.history || [];
        console.log(`Found ${history.length} versions`);

        return history.map(version => ({
            id: version.version,
            description: `Backup from ${new Date(version.committed_at).toLocaleString()}`,
            created_at: version.committed_at,
            updated_at: version.committed_at
        }));
    } catch (error) {
        console.error('Error fetching GitHub versions:', error);
        return { error: 'Failed to fetch backup versions', details: error.message };
    }
}

async function handleGitHubRestore(request, env) {
    const url = new URL(request.url);
    const versionId = url.searchParams.get('id');
    const token = await env.TOTP_STORE.get('github_token');
    const gistId = await env.TOTP_STORE.get('gist_id');
    if (!token || !gistId) {
        return { error: 'Not authenticated with GitHub or no backup found' };
    }

    try {
        console.log(`Restoring version ${versionId} of gist ${gistId}`);
        const response = await fetch(`https://api.github.com/gists/${gistId}/${versionId}`, {
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
            }
        });

        if (!response.ok) {
            const errorBody = await response.text();
            console.error(`GitHub API error: ${response.status} ${response.statusText}`);
            console.error(`Error body: ${errorBody}`);
            throw new Error(`GitHub API responded with status ${response.status}: ${errorBody}`);
        }

        const gistData = await response.json();
        console.log('Gist data received:', JSON.stringify(gistData, null, 2));

        const content = gistData.files['totp_backup.json'].content;
        const totps = JSON.parse(content);

        // Clear existing TOTPs
        await handleClearAllTOTPs(env);

        // Add restored TOTPs
        for (const totp of totps) {
            await env.TOTP_STORE.put(totp.id, JSON.stringify(totp));
        }

        console.log(`Restored ${totps.length} TOTPs`);
        return { message: 'Data restored from Gist successfully', count: totps.length };
    } catch (error) {
        console.error('Error restoring from GitHub:', error);
        return { error: 'Failed to restore data from Gist', details: error.message };
    }
}

async function handleGitHubDeleteBackup(request, env) {
    const token = await env.TOTP_STORE.get('github_token');
    const gistId = await env.TOTP_STORE.get('gist_id');
    if (!token || !gistId) {
        return { error: 'Not authenticated with GitHub or no backup found' };
    }

    try {
        console.log(`Deleting gist ${gistId}`);
        const response = await fetch(`https://api.github.com/gists/${gistId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
            }
        });

        if (!response.ok) {
            const errorBody = await response.text();
            console.error(`GitHub API error: ${response.status} ${response.statusText}`);
            console.error(`Error body: ${errorBody}`);
            throw new Error(`GitHub API responded with status ${response.status}: ${errorBody}`);
        }

        await env.TOTP_STORE.delete('gist_id');
        console.log('Backup deleted successfully');
        return { message: 'Backup deleted successfully' };
    } catch (error) {
        console.error('Error deleting backup:', error);
        return { error: 'Failed to delete backup', details: error.message };
    }
}

export default {
    async fetch(request, env, ctx) {
        const corsHeaders = handleCors();
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders });
        }

        try {
            const url = new URL(request.url);
            const path = url.pathname;

            let response;

            if (path === '/api/totp' && request.method === 'GET') {
                response = await handleErrors(request, () => handleGetTOTPs(env));
            } else if (path === '/api/totp' && request.method === 'POST') {
                response = await handleErrors(request, () => handleAddTOTP(request, env));
            } else if (path.startsWith('/api/totp/') && request.method === 'DELETE') {
                response = await handleErrors(request, () => handleDeleteTOTP(request, env));
            } else if (path.match(/^\/api\/totp\/[^/]+\/generate$/) && request.method === 'GET') {
                response = await handleErrors(request, () => handleGenerateToken(request, env));
            } else if (path.match(/^\/api\/totp\/[^/]+\/export$/) && request.method === 'GET') {
                response = await handleErrors(request, () => handleExportTOTP(request, env));
            } else if (path === '/api/totp/clear-all' && request.method === 'POST') {
                response = await handleErrors(request, () => handleClearAllTOTPs(env));
            } else if (path === '/api/totp/import' && request.method === 'POST') {
                response = await handleErrors(request, () => handleImportTOTP(request, env));
            } else if (path === '/api/cleanup-kv' && request.method === 'POST') {
                response = await handleErrors(request, () => handleCleanupKV(env));
            } else if (path === '/api/github/auth-status' && request.method === 'GET') {
                response = await handleErrors(request, () => handleGitHubAuthStatus(env));
            } else if (path === '/api/github/auth' && request.method === 'GET') {
                return await handleErrors(request, () => handleGitHubAuth(request, env));
            } else if (path === '/api/github/callback' && request.method === 'GET') {
                return await handleErrors(request, () => handleGitHubCallback(request, env));
            } else if (path === '/api/github/upload' && request.method === 'POST') {
                response = await handleErrors(request, () => handleGitHubUpload(request, env));
            } else if (path === '/api/github/versions' && request.method === 'GET') {
                response = await handleErrors(request, () => handleGitHubVersions(env));
            } else if (path === '/api/github/restore' && request.method === 'GET') {
                response = await handleErrors(request, () => handleGitHubRestore(request, env));
            } else if (path === '/api/github/delete-backup' && request.method === 'DELETE') {
                response = await handleErrors(request, () => handleGitHubDeleteBackup(request, env));
            } else {
                return new Response(JSON.stringify({ error: 'Not Found' }), {
                    status: 404,
                    headers: { 'Content-Type': 'application/json', ...corsHeaders }
                });
            }

            // 如果响应已经是 Response 对象，直接返回
            if (response instanceof Response) {
                return response;
            }

            // 否则，创建一个新的 Response 对象
            return new Response(JSON.stringify(response), {
                headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });

        } catch (error) {
            console.error('Unhandled error:', error);
            return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
                status: 500,
                headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
        }
    }
};