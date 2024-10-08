import {nanoid} from 'nanoid';
import {authenticator} from 'otplib';
import jwt from '@tsndr/cloudflare-worker-jwt';
import crypto from 'crypto';

// 辅助函数
const jsonResponse = (data, status = 200, additionalHeaders = {}) => {
    const headers = {
        'Content-Type': 'application/json',
        ...additionalHeaders,
    };
    return new Response(JSON.stringify(data), {status, headers});
};
const createToken = (payload, secret) => {
    return jwt.sign(payload, secret, {expiresIn: '1h'});
};
const handleCors = () => {
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Credentials': 'true',
    };
};

const handleErrors = async (request, func) => {
    try {
        return await func();
    } catch (error) {
        console.error('Error details:', error);
        console.error('Error stack:', error.stack);
        return jsonResponse({error: error.message}, 500);
    }
};

const isLoggedIn = async (request, env) => {
    const sessionData = await env.USER_STORE.get('session');
    if (sessionData) {
        try {
            const session = JSON.parse(sessionData);
            return session.isLoggedIn;
        } catch (error) {
            console.error('Error parsing session data:', error);
            return false;
        }
    }
    return false;
};

const parseOtpMigrationData = (binaryData) => {
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
};

const parseTOTPEntry = (data) => {
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
        return {userInfo, secret};
    }

    return null;
};

const base32Encode = (buffer) => {
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
};

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

const utf8Decode = (buffer) => {
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
};

async function handleGetTOTPs(env) {
    const sessionData = await env.USER_STORE.get('session');
    const session = JSON.parse(sessionData);
    const userPrefix = `${session.username}_`;
    const totps = await env.TOTP_STORE.list();
    const totpList = [];
    for (const key of totps.keys) {
        if (key.name.startsWith(userPrefix) && key.name !== `${userPrefix}github_state` && key.name !== `${userPrefix}github_token` && key.name !== `${userPrefix}gist_id`) {
            try {
                const totpData = await env.TOTP_STORE.get(key.name);
                if (totpData) {
                    const parsedData = JSON.parse(totpData);
                    totpList.push(parsedData);
                }
            } catch (error) {
                console.error(`Error parsing TOTP data for ${key.name}:`, error);
            }
        }
    }
    return jsonResponse(totpList, 200, handleCors());
}

async function handleClearAllTOTPs(env) {
    const sessionData = await env.USER_STORE.get('session');
    const session = JSON.parse(sessionData);
    const userPrefix = `${session.username}_`;
    const totps = await env.TOTP_STORE.list();
    for (const key of totps.keys) {
        if (key.name.startsWith(userPrefix)) {
            await env.TOTP_STORE.delete(key.name);
        }
    }
    return jsonResponse({message: 'All TOTPs cleared successfully'}, 200, handleCors());
}


async function hashPassword(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        {name: "PBKDF2"},
        false,
        ["deriveBits", "deriveKey"]
    );

    return new Promise((resolve, reject) => {
        keyMaterial.then((keyMaterial) => {
            crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: encoder.encode(salt),
                    iterations: 100000,
                    hash: "SHA-256"
                },
                keyMaterial,
                {name: "AES-GCM", length: 256},
                true,
                ["encrypt", "decrypt"]
            ).then((key) => {
                crypto.subtle.exportKey("raw", key).then((exportedKey) => {
                    resolve(btoa(String.fromCharCode(...new Uint8Array(exportedKey))));
                }).catch(reject);
            }).catch(reject);
        }).catch(reject);
    });
};

export default {
    async fetch(request, env, ctx) {
        const requestUrl = new URL(request.url);
        const corsHeaders = handleCors();

        if (request.method === 'OPTIONS') {
            return new Response(null, {status: 204, headers: corsHeaders});
        }

        try {
            // 用户注册
            if (requestUrl.pathname === '/api/register' && request.method === 'POST') {
                const {username, password} = await request.json();
                if (!username || !password) {
                    return jsonResponse({error: 'Username and password are required'}, 400);
                }
                const hashedPassword = await hashPassword(password, env.ENCRYPTION_KEY);
                const id = nanoid();
                const user = {id, username, password: hashedPassword, createdAt: new Date().toISOString()};
                await env.USER_STORE.put(id, JSON.stringify(user));
                const tokenPromise = createToken({user}, env.JWT_SECRET);
                const token = await tokenPromise;
                // 设置会话信息，表示用户已注册并登录
                await env.USER_STORE.put('session', JSON.stringify({isLoggedIn: true, username}));
                return jsonResponse(token, 201, corsHeaders);
            }

            // 用户登录
            if (requestUrl.pathname === '/api/login' && request.method === 'POST') {
                const {username, password} = await request.json();
                if (!username || !password) {
                    return jsonResponse({error: 'Username and password are required'}, 400);
                }
                const users = await env.USER_STORE.list();
                for await (const key of users.keys) {
                    const userData = await env.USER_STORE.get(key.name);
                    if (userData) {
                        const parsedUser = JSON.parse(userData);
                        const hashedPassword = await hashPassword(password, env.ENCRYPTION_KEY);
                        if (parsedUser.username === username && parsedUser.password === hashedPassword) {
                            const tokenPromise = createToken({username}, env.JWT_SECRET);
                            const token = await tokenPromise;
                            await env.USER_STORE.put('session', JSON.stringify({isLoggedIn: true, username}));
                            return jsonResponse({
                                message: 'Login successful',
                                user: {id: parsedUser.id, username: parsedUser.username},
                                token
                            }, 200, corsHeaders);
                        }
                    }
                }
                return jsonResponse({error: 'Invalid username or password'}, 401, corsHeaders);
            }

            // 退出登录
            if (requestUrl.pathname === '/api/logout' && request.method === 'POST') {
                // 删除会话信息
                await env.USER_STORE.delete('session');
                await env.TOTP_STORE.delete('github_token')
                return jsonResponse({message: 'Logout successful'}, 200, corsHeaders);
            }

            // TOTP 相关函数
            if (requestUrl.pathname === '/api/totp' && request.method === 'GET') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401);
                }
                const sessionData = await env.USER_STORE.get('session');
                const session = JSON.parse(sessionData);
                const userPrefix = `${session.username}_`;
                const totps = await env.TOTP_STORE.list();
                const totpList = [];
                for (const key of totps.keys) {
                    if (key.name.startsWith(userPrefix) && key.name !== `${userPrefix}github_state` && key.name !== `${userPrefix}github_token` && key.name !== `${userPrefix}gist_id`) {
                        try {
                            const totpData = await env.TOTP_STORE.get(key.name);
                            if (totpData) {
                                const parsedData = JSON.parse(totpData);
                                totpList.push(parsedData);
                            }
                        } catch (error) {
                            console.error(`Error parsing TOTP data for ${key.name}:`, error);
                        }
                    }
                }
                return jsonResponse(totpList, 200, corsHeaders);
            }

            if (requestUrl.pathname === '/api/totp' && request.method === 'POST') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401);
                }
                const sessionData = await env.USER_STORE.get('session');
                const session = JSON.parse(sessionData);
                const {userInfo, secret} = await request.json();
                if (!userInfo || !secret) {
                    return jsonResponse({error: 'User info and secret are required'}, 400);
                }
                const id = nanoid();
                const userPrefix = `${session.username}_`;
                const totp = {id, userInfo, secret, createdAt: new Date().toISOString(), username: session.username};
                await env.TOTP_STORE.put(`${userPrefix}${id}`, JSON.stringify(totp));
                return jsonResponse(totp, 201, corsHeaders);
            }

            if (requestUrl.pathname.startsWith('/api/totp/') && request.method === 'DELETE') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401);
                }
                const id = requestUrl.pathname.split('/').pop();
                const sessionData = await env.USER_STORE.get('session');
                const session = JSON.parse(sessionData);
                const userPrefix = `${session.username}_`;
                const totpData = await env.TOTP_STORE.get(`${userPrefix}${id}`);
                if (totpData) {
                    const parsedData = JSON.parse(totpData);
                    if (parsedData.username === session.username) {
                        await env.TOTP_STORE.delete(`${userPrefix}${id}`);
                        return jsonResponse({message: 'TOTP deleted successfully'}, 200, corsHeaders);
                    }
                }
                return jsonResponse({error: 'You are not authorized to delete this TOTP'}, 403, corsHeaders);
            }

            if (requestUrl.pathname.match(/^\/api\/totp\/[^/]+\/generate$/) && request.method === 'GET') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401);
                }
                const id = requestUrl.pathname.split('/').slice(-2)[0];
                const sessionData = await env.USER_STORE.get('session');
                const session = JSON.parse(sessionData);
                const userPrefix = `${session.username}_`;
                const totpData = await env.TOTP_STORE.get(`${userPrefix}${id}`);
                if (!totpData) {
                    console.error('TOTP not found for ID:', id);
                    return jsonResponse({error: 'TOTP not found'}, 404);
                }
                try {
                    const totp = JSON.parse(totpData);
                    if (totp.username === session.username) {
                        const token = authenticator.generate(totp.secret);
                        return jsonResponse({token}, 200, corsHeaders);
                    } else {
                        return jsonResponse({error: 'You are not authorized to generate token for this TOTP'}, 403, corsHeaders);
                    }
                } catch (error) {
                    console.error('Error generating token:', error);
                    return jsonResponse({error: 'Failed to generate token'}, 500, corsHeaders);
                }
            }

            if (requestUrl.pathname.match(/^\/api\/totp\/[^/]+\/export$/) && request.method === 'GET') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401);
                }
                const id = requestUrl.pathname.split('/').slice(-2)[0];
                const sessionData = await env.USER_STORE.get('session');
                const session = JSON.parse(sessionData);
                const userPrefix = `${session.username}_`;
                const totpData = await env.TOTP_STORE.get(`${userPrefix}${id}`);
                if (!totpData) {
                    console.error('TOTP not found for ID:', id);
                    return jsonResponse({error: 'TOTP not found'}, 404);
                }
                try {
                    const totp = JSON.parse(totpData);
                    if (totp.username === session.username) {
                        const uri = authenticator.keyuri(totp.userInfo, 'TOTP Manager', totp.secret);
                        return jsonResponse({uri}, 200, corsHeaders);
                    } else {
                        return jsonResponse({error: 'You are not authorized to export this TOTP'}, 403, corsHeaders);
                    }
                } catch (error) {
                    console.error('Error exporting TOTP:', error);
                    return jsonResponse({error: 'Failed to export TOTP'}, 500, corsHeaders);
                }
            }

            if (requestUrl.pathname === '/api/totp/clear-all' && request.method === 'POST') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401);
                }
                await handleClearAllTOTPs(env);
                return jsonResponse({message: 'All your TOTPs cleared successfully'}, 200, corsHeaders);
            }

            if (requestUrl.pathname === '/api/totp/import' && request.method === 'POST') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401);
                }
                const {qrData} = await request.json();
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
                            console.error('Invalid QR code data:', {secret, userInfo});
                            return jsonResponse({error: 'Invalid QR code data'}, 400);
                        }

                        totps = [{userInfo, secret}];
                    } else {
                        return jsonResponse({error: 'Unsupported QR code format'}, 400);
                    }

                    if (!Array.isArray(totps) || totps.length === 0) {
                        return jsonResponse({error: 'No valid TOTP entries found'}, 400);
                    }

                    const sessionData = await env.USER_STORE.get('session');
                    const session = JSON.parse(sessionData);
                    const userPrefix = `${session.username}_`;

                    for (const totp of totps) {
                        const id = nanoid();
                        await env.TOTP_STORE.put(`${userPrefix}${id}`, JSON.stringify({
                            id,
                            userInfo: totp.userInfo,
                            secret: totp.secret,
                            createdAt: new Date().toISOString(),
                            username: session.username
                        }));
                    }

                    console.log('TOTPs imported successfully:', totps.length);
                    return jsonResponse({success: true, count: totps.length}, 200, corsHeaders);
                } catch (error) {
                    console.error('Import TOTP error:', error);
                    return jsonResponse({error: 'Failed to import TOTP: ' + error.message}, 400);
                }
            }
            // GitHub 相关函数
            if (requestUrl.pathname === '/api/github/auth-status' && request.method === 'GET') {
                const token = await env.TOTP_STORE.get('github_token');
                return jsonResponse({authenticated: !!token}, 200, corsHeaders);
            }

            if (requestUrl.pathname === '/api/github/auth' && request.method === 'GET') {
                const clientId = env.GITHUB_CLIENT_ID;
                const redirectUri = env.GITHUB_REDIRECT_URI;
                const state = nanoid();
                await env.TOTP_STORE.put('github_state', state, {expirationTtl: 600});
                const authUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}&scope=gist`;
                return new Response(null, {
                    status: 302,
                    headers: {
                        'Location': authUrl,
                        ...corsHeaders
                    }
                });
            }

            if (requestUrl.pathname === '/api/github/callback' && request.method === 'GET') {
                const code = requestUrl.searchParams.get('code');
                const state = requestUrl.searchParams.get('state');

                const savedState = await env.TOTP_STORE.get('github_state');
                if (state !== savedState) {
                    return new Response(JSON.stringify({error: 'Invalid state'}), {
                        status: 400,
                        headers: {'Content-Type': 'application/json', ...corsHeaders}
                    });
                }
                ;
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
                            ...corsHeaders
                        }
                    });
                } else {
                    console.error('Failed to obtain GitHub access token:', tokenData);
                    return new Response(JSON.stringify({error: 'Failed to obtain access token'}), {
                        status: 400,
                        headers: {'Content-Type': 'application/json', ...corsHeaders}
                    });
                }
            }

            if (requestUrl.pathname === '/api/github/upload' && request.method === 'POST') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401);
                }
                let mode;
                try {
                    const body = await request.json();
                    mode = body.mode;
                } catch (error) {
                    console.error('Error parsing request body:', error);
                    return {error: 'Invalid request body'};
                }
                const token = await env.TOTP_STORE.get('github_token');
                if (!token) {
                    return jsonResponse({error: 'Not authenticated with GitHub'}, 401, corsHeaders);
                }
                const sessionData = await env.USER_STORE.get('session');
                const session = JSON.parse(sessionData);
                const totps = await handleGetTOTPs(env);
                const filteredTotps = totps.filter(totp => totp.username === session.username);
                const content = JSON.stringify(filteredTotps);
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
                        description: 'TOTP Backup',
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
                        return jsonResponse({
                            message: 'Data uploaded to Gist successfully',
                            gistId: data.id
                        }, 200, corsHeaders);
                    } else {
                        return jsonResponse({error: 'Failed to upload data to Gist', details: data}, 500, corsHeaders);
                    }
                } catch (error) {
                    console.error('Error uploading to GitHub:', error);
                    return jsonResponse({
                        error: 'Failed to upload data to Gist',
                        details: error.message
                    }, 500, corsHeaders);
                }
            }

            if (requestUrl.pathname === '/api/github/versions' && request.method === 'GET') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401, corsHeaders);
                }
                const token = await env.TOTP_STORE.get('github_token');
                const gistId = await env.TOTP_STORE.get('gist_id');
                if (!token || !gistId) {
                    console.error('GitHub token or gist ID not found');
                    return jsonResponse({error: 'Not authenticated with GitHub or no backup found'}, 401, corsHeaders);
                }
                try {
                    console.log(`Fetching versions for gist: ${gistId}`);
                    const response = await fetch(`https://api.github.com/gists/${gistId}`, {
                        headers: {
                            'Authorization': token,
                            'Accept': 'application/vnd.github.v3+json',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
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
                    return jsonResponse(history.map(version => ({
                        id: version.version,
                        description: `Backup from ${new Date(version.committed_at).toLocaleString()}`,
                        created_at: version.committed_at,
                        updated_at: version.committed_at
                    })), 200, corsHeaders);
                } catch (error) {
                    console.error('Error fetching GitHub versions:', error);
                    return jsonResponse({
                        error: 'Failed to fetch backup versions',
                        details: error.message
                    }, 500, corsHeaders);
                }
            }

            if (requestUrl.pathname === '/api/github/restore' && request.method === 'GET') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401, corsHeaders);
                }
                const token = await env.TOTP_STORE.get('github_token');
                const gistId = await env.TOTP_STORE.get('gist_id');
                if (!token || !gistId) {
                    return jsonResponse({error: 'Not authenticated with GitHub or no backup found'}, 401, corsHeaders);
                }
                try {
                    console.log(`Restoring version ${gistId}`);
                    const response = await fetch(`https://api.github.com/gists/${gistId}`, {
                        headers: {
                            'Authorization': `token ${token}`,
                            'Accept': 'application/vnd.github.v3+json',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
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
                    const sessionData = await env.USER_STORE.get('session');
                    const session = JSON.parse(sessionData);
                    // Clear existing TOTPs for the logged-in user
                    await handleClearAllTOTPs(env, session.username);
                    // Add restored TOTPs for the logged-in user
                    for (const totp of totps) {
                        if (totp.username === session.username) {
                            await env.TOTP_STORE.put(totp.id, JSON.stringify(totp));
                        }
                    }
                    console.log(`Restored ${totps.length} TOTPs for the user`);
                    return jsonResponse({
                        message: 'Data restored from Gist successfully',
                        count: totps.length
                    }, 200, corsHeaders);
                } catch (error) {
                    console.error('Error restoring from GitHub:', error);
                    return jsonResponse({
                        error: 'Failed to restore data from Gist',
                        details: error.message
                    }, 500, corsHeaders);
                }
            }

            if (requestUrl.pathname === '/api/github/delete-backup' && request.method === 'DELETE') {
                if (!isLoggedIn(request, env)) {
                    return jsonResponse({error: 'Not logged in'}, 401, corsHeaders);
                }
                const token = await env.TOTP_STORE.get('github_token');
                const gistId = await env.TOTP_STORE.get('gist_id');
                if (!token || !gistId) {
                    return jsonResponse({error: 'Not authenticated with GitHub or no backup found'}, 401, corsHeaders);
                }
                try {
                    console.log(`Deleting gist ${gistId}`);
                    const response = await fetch(`https://api.github.com/gists/${gistId}`, {
                        method: 'DELETE',
                        headers: {
                            'Authorization': `token ${token}`,
                            'Accept': 'application/vnd.github.v3+json',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
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
                    return jsonResponse({message: 'Backup deleted successfully'}, 200, corsHeaders);
                } catch (error) {
                    console.error('Error deleting backup:', error);
                    return jsonResponse({error: 'Failed to delete backup', details: error.message}, 500, corsHeaders);
                }
            }

            // 404 错误处理
            return jsonResponse({error: 'Not Found'}, 404, corsHeaders);
        } catch (error) {
            console.error('Unhandled error:', error);
            return jsonResponse({error: 'Internal Server Error'}, 500, corsHeaders);
        }
    }
};
