const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const momentTimezone = require('moment-timezone');
const fs = require('fs');
const { URLSearchParams } = require('url');
const shortid = require('shortid');
const stableStringify = require('json-stable-stringify');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(cors());

// --- KONSTAN KONFIGURASI API ---
const CLIENT_ID = '0199dc00-f2df-74b1-95e4-8664bdaaa9dd';
const CLIENT_SECRET = '425f8e4a-0f0c-474a-aa4f-64538f87bed4.0d.DIYVm+96QGa0mCg2X5JxRSG79BuHQJw+YGPV7aCuUIk=';
const BASE_URL = 'https://natsu-api-sandbox.smbpay.id';
const CLIENT_TOKEN_URL = `${BASE_URL}/oauth/token`;
const B2B_TOKEN_ENDPOINT = '/v2.0/access-token/b2b/';
const B2B2C_TOKEN_ENDPOINT = '/v2.0/access-token/b2b2c/';
const B2B2C_TOKEN_URL = `${BASE_URL}${B2B2C_TOKEN_ENDPOINT}`;

// --- KONSTAN DATA PENGGUNA/PERANGKAT ---
const DEVICE_ID = '962bdf1c-5d28-4c46-b67b-265457d5c08a';
const AUTH_CODE = '0dde3b4745b22fdb9c535f8cae9af7cd';
const IP_ADDRESS = '192.168.1.1';
const LATITUDE = '-6.200000';
const LONGITUDE = '106.816666';

// --- KONSTAN ENDPOINT TRANSAKSI ---
const ACCOUNT_PROFILE_RELATIVE_PATH = '/cobrand-saving/v2.0/account-profile/';
const BALANCE_INQUIRY_RELATIVE_PATH = '/cobrand-saving/v1.0/balance-inquiry/';
const CHANGE_MPIN_RELATIVE_PATH = '/cobrand-saving/v1.0/change-pin/';
const RESET_MPIN_RELATIVE_PATH = '/cobrand-saving/v1.0/reset-mpin/';
const TRANSACTION_HISTORY_RELATIVE_PATH = '/cobrand-saving/v1.0/transaction-history-list/';
const CARD_PROFILE_RELATIVE_PATH = '/cobrand-saving/v1.0/card-inquiry/';

const ACCOUNT_PROFILE_URL = `${BASE_URL}${ACCOUNT_PROFILE_RELATIVE_PATH}`;
const BALANCE_INQUIRY_URL = `${BASE_URL}${BALANCE_INQUIRY_RELATIVE_PATH}`;
const CHANGE_MPIN_URL = `${BASE_URL}${CHANGE_MPIN_RELATIVE_PATH}`;
const RESET_MPIN_URL = `${BASE_URL}${RESET_MPIN_RELATIVE_PATH}`;
const TRANSACTION_HISTORY_URL = `${BASE_URL}${TRANSACTION_HISTORY_RELATIVE_PATH}`;
const CARD_PROFILE_URL = `${BASE_URL}${CARD_PROFILE_RELATIVE_PATH}`;

const PRIVATE_KEY_PATH = './private.pem';


let clientAccessToken = null;
let b2bAccessToken = null;
let b2b2cAccessToken = null;


// --- FUNGSI UTILITY SIGNATURE ---

const createAsymmetricSignature = (srvTimestamp, clientId, privateKeyPath) => {
    try {
        const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
        const stringToSign = `${clientId}|${srvTimestamp}`;
        const signer = crypto.createSign('RSA-SHA256');
        signer.update(stringToSign);
        const signature = signer.sign(privateKey, 'base64');
        return { signature, stringToSign };
    } catch (e) {
        throw new Error('Asymmetric signature creation failed.');
    }
};

const generateSymmetricSignature = (
    method,
    path,
    accessToken,
    payload,
    timestamp,
    secretKey
) => {
    let jsonString = stableStringify(payload);

    const hash = crypto.createHash('sha256').update(jsonString).digest('hex').toLowerCase();

    const stringToSign = [
        method,
        path,
        accessToken,
        hash,
        timestamp
    ].join(':');

    const hmacHex = crypto.createHmac('sha512', secretKey)
        .update(stringToSign)
        .digest('hex');

    const signature = Buffer.from(hmacHex).toString('base64');

    return { signature, stringToSign, hash, jsonString };
};


// --- FUNGSI OTENTIKASI ---

const getClientToken = async () => {
    const data = { grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET };
    const payload = new URLSearchParams(data).toString();
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    try {
        const response = await axios.post(CLIENT_TOKEN_URL, payload, { headers });
        clientAccessToken = response.data.access_token;
        return clientAccessToken;
    } catch (error) {
        return null;
    }
};

const getB2BToken = async () => {
    if (!clientAccessToken) return null;
    const srvTimestamp = momentTimezone().tz('Asia/Jakarta').format('YYYY-MM-DDTHH:mm:ss') + '+07:00';
    try {
        const { signature } = createAsymmetricSignature(srvTimestamp, CLIENT_ID, PRIVATE_KEY_PATH);
        const requestBody = JSON.stringify({ "grantType": "client_credentials", "additionalInfo": {} });
        const headers = {
            'X-TIMESTAMP': srvTimestamp, 'X-SIGNATURE': signature, 'X-CLIENT-KEY': CLIENT_ID,
            'Authorization': `Bearer ${clientAccessToken}`, 'Content-Type': 'application/json'
        };
        const response = await axios.post(`${BASE_URL}${B2B_TOKEN_ENDPOINT}`, requestBody, { headers });
        b2bAccessToken = response.data.accessToken;
        return b2bAccessToken;
    } catch (error) {
        return null;
    }
};

const getB2B2CToken = async () => {
    const httpMethod = 'POST';
    const relativePath = B2B2C_TOKEN_ENDPOINT;

    if (!b2bAccessToken) {
        throw new Error('B2B Token is not available to retrieve B2B2C token.');
    }

    const authCode = AUTH_CODE;
    const srvTimestamp = momentTimezone().tz('Asia/Jakarta').format('YYYY-MM-DDTHH:mm:ss') + '+07:00';

    const requestBodyObj = {
        "grantType": "authorization_code",
        "authCode": authCode
    };

    try {
        const { signature, jsonString } = generateSymmetricSignature(
            httpMethod, relativePath, b2bAccessToken, requestBodyObj, srvTimestamp, CLIENT_SECRET
        );

        const headers = {
            'X-TIMESTAMP': srvTimestamp, 'X-SIGNATURE': signature, 'X-CLIENT-KEY': CLIENT_ID,
            'X-DEVICE-ID': DEVICE_ID, 'X-LATITUDE': LATITUDE, 'X-LONGITUDE': LONGITUDE,
            'X-IP-ADDRESS': IP_ADDRESS, 'Authorization': `Bearer ${b2bAccessToken}`,
            'Content-Type': 'application/json'
        };

        const response = await axios.post(B2B2C_TOKEN_URL, jsonString, { headers });

        return response.data.accessToken;

    } catch (error) {
        if (error.response) {
            throw new Error(`Failed to get B2B2C Token: ${error.response.data.responseMessage || error.response.status}`);
        } else {
            throw new Error(`Network error during B2B2C Token retrieval: ${error.message}`);
        }
    }
};


// --- FUNGSI UTILITY TRANSAKSI (Ditambahkan Logging Detail) ---

const executeTransaction = async (httpMethod, relativePath, requestBodyObj, apiUrl, endpointName) => {
    const logPrefix = `[${endpointName.toUpperCase()}]`;

    if (!b2bAccessToken || !b2b2cAccessToken) {
        console.error(`${logPrefix} ❌ GAGAL: Token otentikasi B2B/B2B2C belum siap.`);
        return { status: 503, data: { responseMessage: 'Authentication tokens are not ready. Please wait for server initialization.' } };
    }

    const srvTimestamp = momentTimezone().tz('Asia/Jakarta').format('YYYY-MM-DDTHH:mm:ss') + '+07:00';

    // Log Request
    console.log(`\n${logPrefix} ➡️ REQUEST (${new Date().toLocaleTimeString()}):`);
    console.log(`Endpoint: ${relativePath}`);
    console.log(`Body: ${JSON.stringify(requestBodyObj)}`);
    console.log('--------------------------------------------------');


    try {
        const { signature, jsonString } = generateSymmetricSignature(
            httpMethod, relativePath, b2bAccessToken, requestBodyObj, srvTimestamp, CLIENT_SECRET
        );

        const headers = {
            'Authorization-Customer': `Bearer ${b2b2cAccessToken}`,
            'X-TIMESTAMP': srvTimestamp,
            'X-SIGNATURE': signature,
            'X-CLIENT-KEY': CLIENT_ID,
            'X-DEVICE-ID': DEVICE_ID,
            'X-IP-ADDRESS': IP_ADDRESS,
            'X-LATITUDE': LATITUDE,
            'X-LONGITUDE': LONGITUDE,
            'Authorization': `Bearer ${b2bAccessToken}`,
            'Content-Type': 'application/json',
        };

        const response = await axios.post(apiUrl, jsonString, { headers });

        // Log Sukses
        console.log(`${logPrefix} ✅ SUKSES (HTTP ${response.status}):`);
        console.log(`Response Code: ${response.data.responseCode}`);
        console.log(`Response Message: ${response.data.responseMessage}`);
        console.log(`Data: ${JSON.stringify(response.data)}`);
        console.log('--------------------------------------------------');


        return { status: response.status, data: response.data };

    } catch (error) {
        if (error.response) {
            // Log Error API
            console.error(`${logPrefix} ❌ ERROR API (HTTP ${error.response.status}):`);
            console.error(`Response Code: ${error.response.data.responseCode || 'N/A'}`);
            console.error(`Response Data: ${JSON.stringify(error.response.data)}`);
            console.log('--------------------------------------------------');
            return { status: error.response.status, data: error.response.data };
        } else {
            // Log Error Jaringan
            console.error(`${logPrefix} ❌ ERROR JARINGAN:`);
            console.error(`Detail: ${error.message}`);
            console.log('--------------------------------------------------');
            return { status: 500, data: { responseMessage: `Network error: ${error.message}` } };
        }
    }
};


// --- FUNGSI TRANSAKSI UTAMA (Diperbarui dengan endpointName) ---

const getAccountProfile = (accountId) => {
    const requestBodyObj = { "partnerReferenceNo": shortid.generate(), "additionalInfo": { "accountId": accountId } };
    return executeTransaction('POST', ACCOUNT_PROFILE_RELATIVE_PATH, requestBodyObj, ACCOUNT_PROFILE_URL, 'Account Profile');
};

const getBalanceInquiry = (accountId) => {
    const requestBodyObj = { "partnerReferenceNo": shortid.generate(), "additionalInfo": { "accountId": accountId } };
    return executeTransaction('POST', BALANCE_INQUIRY_RELATIVE_PATH, requestBodyObj, BALANCE_INQUIRY_URL, 'Balance Inquiry');
};

const postChangeMPIN = (accountId, email, phoneNo) => {
    const requestBodyObj = {
        "partnerReferenceNo": shortid.generate(),
        "email": email,
        "phoneNo": phoneNo,
        "additionalInfo": { "accountId": accountId }
    };
    return executeTransaction('POST', CHANGE_MPIN_RELATIVE_PATH, requestBodyObj, CHANGE_MPIN_URL, 'Change MPIN');
};

const postResetMPIN = (accountId, referenceNo) => {
    const requestBodyObj = {
        "partnerReferenceNo": shortid.generate(),
        "referenceNo": referenceNo,
        "additionalInfo": { "accountId": accountId }
    };
    return executeTransaction('POST', RESET_MPIN_RELATIVE_PATH, requestBodyObj, RESET_MPIN_URL, 'Reset MPIN');
};

const getTransactionHistory = (accountId, fromDateTime, toDateTime, pageId = null, lastTrxDate = null) => {
    const requestBodyObj = {
        "partnerReferenceNo": shortid.generate(),
        "fromDateTime": fromDateTime,
        "toDateTime": toDateTime,
        "additionalInfo": {
            "accountId": accountId,
            "pageId": pageId,
            "lastTrxDate": lastTrxDate
        }
    };
    return executeTransaction('POST', TRANSACTION_HISTORY_RELATIVE_PATH, requestBodyObj, TRANSACTION_HISTORY_URL, 'Transaction History');
};

const getCardProfile = (accountId) => {
    const requestBodyObj = { "partnerReferenceNo": shortid.generate(), "additionalInfo": { "accountId": accountId } };
    return executeTransaction('POST', CARD_PROFILE_RELATIVE_PATH, requestBodyObj, CARD_PROFILE_URL, 'Card Profile');
};


// --- ROUTES ---

app.use(express.json());

// 1. Account Profile
app.post('/api/account-profile', async (req, res) => {
    const { accountId } = req.body;
    if (!accountId) return res.status(400).json({ responseMessage: 'accountId is required.' });

    const result = await getAccountProfile(accountId);
    res.status(result.status).json(result.data);
});

// 2. Balance Inquiry
app.post('/api/balance-inquiry', async (req, res) => {
    const { accountId } = req.body;
    if (!accountId) return res.status(400).json({ responseMessage: 'accountId is required.' });

    const result = await getBalanceInquiry(accountId);
    res.status(result.status).json(result.data);
});

// 3. Change MPIN
app.post('/api/change-mpin', async (req, res) => {
    const { accountId, email, phoneNo } = req.body;
    if (!accountId || !email || !phoneNo) {
        return res.status(400).json({ responseMessage: 'accountId, email, and phoneNo are required.' });
    }

    // Logging sudah ditambahkan di fungsi postChangeMPIN melalui executeTransaction
    const result = await postChangeMPIN(accountId, email, phoneNo);
    res.status(result.status).json(result.data);
});

// 4. Reset MPIN
app.post('/api/reset-mpin', async (req, res) => {
    const { accountId, referenceNo } = req.body;
    if (!accountId || !referenceNo) {
        return res.status(400).json({ responseMessage: 'accountId and referenceNo are required.' });
    }

    // Logging sudah ditambahkan di fungsi postResetMPIN melalui executeTransaction
    const result = await postResetMPIN(accountId, referenceNo);
    res.status(result.status).json(result.data);
});

// 5. Transaction History
app.post('/api/transaction-history', async (req, res) => {
    const { accountId, fromDateTime, toDateTime, pageId, lastTrxDate } = req.body;
    if (!accountId || !fromDateTime || !toDateTime) {
        return res.status(400).json({ responseMessage: 'accountId, fromDateTime, and toDateTime are required.' });
    }

    const result = await getTransactionHistory(accountId, fromDateTime, toDateTime, pageId, lastTrxDate);
    res.status(result.status).json(result.data);
});

// 6. Card Profile
app.post('/api/card-profile', async (req, res) => {
    const { accountId } = req.body;
    if (!accountId) return res.status(400).json({ responseMessage: 'accountId is required.' });

    // Logging sudah ditambahkan di fungsi getCardProfile melalui executeTransaction
    const result = await getCardProfile(accountId);
    res.status(result.status).json(result.data);
});


// --- LISTEN ---

app.listen(port, async () => {
    console.log(`Server berjalan di http://localhost:${port}`);
    console.log('--- Token Initialization ---');

    try {
        const tokenKlien = await getClientToken();
        if (!tokenKlien) throw new Error('Failed to get Client Token. Initialization failed.');

        const tokenB2B = await getB2BToken();
        if (!tokenB2B) throw new Error('Failed to get B2B Token. Initialization failed.');
        console.log('✅ B2B Token acquired.');

        b2b2cAccessToken = await getB2B2CToken();
        if (!b2b2cAccessToken) throw new Error('Failed to get B2B2C Access Token.');

        console.log('✅ B2B2C Token acquired. Ready to use.');

    } catch (error) {
        console.error(`\n❌ Fatal Initialization Error: ${error.message}`);
        console.error('Server is running but token setup failed. Check the token values.');
    }
    console.log('------------------------------');
    console.log(`Endpoint tersedia: POST http://localhost:${port}/api/change-mpin (dengan Logging)`);
    console.log(`Endpoint tersedia: POST http://localhost:${port}/api/reset-mpin (dengan Logging)`);
    console.log(`Endpoint tersedia: POST http://localhost:${port}/api/card-profile (dengan Logging)`);
});