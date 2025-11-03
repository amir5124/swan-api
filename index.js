const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const momentTimezone = require('moment-timezone');
const fs = require('fs');
const { URLSearchParams } = require('url');
const shortid = require('shortid');
const stableStringify = require('json-stable-stringify');
const cors = require('cors');

const pool = require('./db/db'); // 1. IMPORT POOL DATABASE

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

const CLIENT_ID = '0199dc00-f2df-74b1-95e4-8664bdaaa9dd';
const CLIENT_SECRET = '425f8e4a-0f0c-474a-aa4f-64538f87bed4.0d.DIYVm+96QGa0mCg2X5JxRSG79BuHQJw+YGPV7aCuUIk=';
const BASE_URL = 'https://natsu-api-sandbox.smbpay.id';
const CLIENT_TOKEN_URL = `${BASE_URL}/oauth/token`;
const B2B_TOKEN_ENDPOINT = '/v2.0/access-token/b2b/';
const B2B2C_TOKEN_ENDPOINT = '/v2.0/access-token/b2b2c/';
const B2B2C_TOKEN_URL = `${BASE_URL}${B2B2C_TOKEN_ENDPOINT}`;

const DEVICE_ID = '962bdf1c-5d28-4c46-b67b-265457d5c08a';
const AUTH_CODE = '0dde3b4745b22fdb9c535f8cae9af7cd';
const IP_ADDRESS = '192.168.1.1';
const LATITUDE = '-6.200000';
const LONGITUDE = '106.816666';

const ACCOUNT_CREATION_RELATIVE_PATH = '/cobrand-saving/v1.0/registration-account-creation/';
const ACCOUNT_INQUIRY_RELATIVE_PATH = '/cobrand-saving/v1.0/registration-account-inquiry/';
const ACCOUNT_PROFILE_RELATIVE_PATH = '/cobrand-saving/v2.0/account-profile/';
const BALANCE_INQUIRY_RELATIVE_PATH = '/cobrand-saving/v1.0/balance-inquiry/';
const CHANGE_MPIN_RELATIVE_PATH = '/cobrand-saving/v1.0/change-pin/';
const RESET_MPIN_RELATIVE_PATH = '/cobrand-saving/v1.0/reset-mpin/';
const TRANSACTION_HISTORY_RELATIVE_PATH = '/cobrand-saving/v1.0/transaction-history-list/';
const CARD_PROFILE_RELATIVE_PATH = '/cobrand-saving/v1.0/card-inquiry/';

const ACCOUNT_CREATION_URL = `${BASE_URL}${ACCOUNT_CREATION_RELATIVE_PATH}`;
const ACCOUNT_INQUIRY_URL = `${BASE_URL}${ACCOUNT_INQUIRY_RELATIVE_PATH}`;
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

const executeB2CTransaction = async (httpMethod, relativePath, requestBodyObj, apiUrl, endpointName) => {
    const logPrefix = `[${endpointName.toUpperCase()}]`;

    if (!b2bAccessToken || !b2b2cAccessToken) {
        return { status: 503, data: { responseMessage: 'Authentication tokens are not ready. Please wait for server initialization.' } };
    }

    const srvTimestamp = momentTimezone().tz('Asia/Jakarta').format('YYYY-MM-DDTHH:mm:ss') + '+07:00';

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

        return { status: response.status, data: response.data };

    } catch (error) {
        if (error.response) {
            return { status: error.response.status, data: error.response.data };
        } else {
            return { status: 500, data: { responseMessage: `Network error: ${error.message}` } };
        }
    }
};

const executeB2BTransaction = async (httpMethod, relativePath, requestBodyObj, apiUrl, endpointName) => {
    const logPrefix = `[${endpointName.toUpperCase()}]`;

    if (!b2bAccessToken) {
        return { status: 503, data: { responseMessage: 'B2B Token is not available. Please wait for server initialization.' } };
    }

    if (!requestBodyObj.referenceNo) {
        requestBodyObj.referenceNo = shortid.generate();
    }

    const srvTimestamp = momentTimezone().tz('Asia/Jakarta').format('YYYY-MM-DDTHH:mm:ss') + '+07:00';

    try {
        const { signature, jsonString } = generateSymmetricSignature(
            httpMethod, relativePath, b2bAccessToken, requestBodyObj, srvTimestamp, CLIENT_SECRET
        );

        const headers = {
            'Authorization': `Bearer ${b2bAccessToken}`,
            'X-TIMESTAMP': srvTimestamp,
            'X-SIGNATURE': signature,
            'X-CLIENT-KEY': CLIENT_ID,
            'X-DEVICE-ID': DEVICE_ID,
            'X-IP-ADDRESS': IP_ADDRESS,
            'X-LATITUDE': LATITUDE,
            'X-LONGITUDE': LONGITUDE,
            'Content-Type': 'application/json',
        };

        const response = await axios.post(apiUrl, jsonString, { headers });

        return { status: response.status, data: response.data };

    } catch (error) {
        if (error.response) {
            return { status: error.response.status, data: error.response.data };
        } else {
            return { status: 500, data: { responseMessage: `Network error: ${error.message}` } };
        }
    }
};


const postAccountCreation = (requestBodyObj) => {
    return executeB2BTransaction('POST', ACCOUNT_CREATION_RELATIVE_PATH, requestBodyObj, ACCOUNT_CREATION_URL, 'Account Creation');
};

const postAccountInquiry = (requestBodyObj) => {
    return executeB2BTransaction('POST', ACCOUNT_INQUIRY_RELATIVE_PATH, requestBodyObj, ACCOUNT_INQUIRY_URL, 'Account Inquiry');
};

const getAccountProfile = (accountId) => {
    const requestBodyObj = { "partnerReferenceNo": shortid.generate(), "additionalInfo": { "accountId": accountId } };
    return executeB2CTransaction('POST', ACCOUNT_PROFILE_RELATIVE_PATH, requestBodyObj, ACCOUNT_PROFILE_URL, 'Account Profile');
};

const getBalanceInquiry = (accountId) => {
    const requestBodyObj = { "partnerReferenceNo": shortid.generate(), "additionalInfo": { "accountId": accountId } };
    return executeB2CTransaction('POST', BALANCE_INQUIRY_RELATIVE_PATH, requestBodyObj, BALANCE_INQUIRY_URL, 'Balance Inquiry');
};

const postChangeMPIN = (accountId, email, phoneNo) => {
    const requestBodyObj = {
        "partnerReferenceNo": shortid.generate(),
        "email": email,
        "phoneNo": phoneNo,
        "additionalInfo": { "accountId": accountId }
    };
    return executeB2CTransaction('POST', CHANGE_MPIN_RELATIVE_PATH, requestBodyObj, CHANGE_MPIN_URL, 'Change MPIN');
};

const postResetMPIN = (accountId, referenceNo) => {
    const requestBodyObj = {
        "partnerReferenceNo": shortid.generate(),
        "referenceNo": referenceNo,
        "additionalInfo": { "accountId": accountId }
    };
    return executeB2CTransaction('POST', RESET_MPIN_RELATIVE_PATH, requestBodyObj, RESET_MPIN_URL, 'Reset MPIN');
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
    return executeB2CTransaction('POST', TRANSACTION_HISTORY_RELATIVE_PATH, requestBodyObj, TRANSACTION_HISTORY_URL, 'Transaction History');
};

const getCardProfile = (accountId) => {
    const requestBodyObj = { "partnerReferenceNo": shortid.generate(), "additionalInfo": { "accountId": accountId } };
    return executeB2CTransaction('POST', CARD_PROFILE_RELATIVE_PATH, requestBodyObj, CARD_PROFILE_URL, 'Card Profile');
};

// 2. FUNGSI UNTUK MENYIMPAN DATA REGISTRASI KE DATABASE
async function saveRegistrationData(reqBody, apiResponse) {
    const {
        userId,
        phoneNo,
        email,
        name,
        partnerReferenceNo,
        additionalInfo
    } = reqBody;

    // Pastikan customerData ada sebelum diakses
    const customerData = additionalInfo?.customerData || {};
    const { idNumber, address } = customerData;

    const {
        responseCode,
        responseMessage,
        state,
        additionalInfo: apiAdditionalInfo
    } = apiResponse;
    const webviewUrl = apiAdditionalInfo?.webViewUrl || null;

    const query = `
        INSERT INTO user_uduit (
            jagel_user_id, phone_no, email, full_name, id_number, address,
            partner_reference_no, api_response_code, api_response_message, api_state, webview_url
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const values = [
        userId,
        phoneNo,
        email,
        name,
        idNumber,
        address,
        partnerReferenceNo,
        responseCode,
        responseMessage,
        state,
        webviewUrl
    ];

    try {
        const [result] = await pool.execute(query, values);
        console.log(`[DB] ✅ Data registrasi user ID ${userId} berhasil disimpan. Insert ID: ${result.insertId}`);
        return result;
    } catch (dbError) {
        console.error(`[DB] ❌ Gagal menyimpan data registrasi untuk user ID ${userId}:`, dbError);
        throw new Error('Database insertion failed');
    }
}

// 3. ENDPOINT VALIDASI STATUS PENGGUNA BARU
app.post('/api/uduit/check-registration', async (req, res) => {
    const { userId } = req.body;

    if (!userId || userId === '{userid}') {
        return res.status(200).json({ isRegistered: false, message: 'User ID is missing or invalid literal.' });
    }

    try {
        const query = 'SELECT jagel_user_id FROM user_uduit WHERE jagel_user_id = ?';
        const [rows] = await pool.execute(query, [userId]);

        const isRegistered = rows.length > 0;

        return res.status(200).json({
            isRegistered: isRegistered,
            message: isRegistered ? 'User is already registered.' : 'User not found in Uduit registration database.'
        });

    } catch (error) {
        console.error('Error checking registration status in DB:', error);
        return res.status(500).json({ isRegistered: false, message: 'Internal server error during database check.' });
    }
});


// 4. MODIFIKASI ENDPOINT ACCOUNT CREATION (PENYIMPANAN DB)
app.post('/api/account-creation', async (req, res) => {

    if (!req.body || !req.body.phoneNo || !req.body.email || !req.body.userId || !req.body.partnerReferenceNo) {
        const errorResponse = { responseMessage: 'Missing mandatory fields: phoneNo, email, userId, or partnerReferenceNo.' };
        return res.status(400).json(errorResponse);
    }
    if (req.body.userId === '{userid}') {
        const errorResponse = { responseMessage: 'userId from Jagel is an invalid literal.' };
        return res.status(400).json(errorResponse);
    }

    const additionalInfo = req.body.additionalInfo;
    if (!additionalInfo || !additionalInfo.imageKtp || !additionalInfo.customerData) {
        const errorResponse = {
            responseCode: "4000000",
            responseMessage: "Missing Mandatory Field { additionalInfo.imageKtp, additionalInfo.customerData }."
        };
        return res.status(400).json(errorResponse);
    }

    const { phoneNo, email, userId } = req.body;

    try {
        const checkQuery = `
            SELECT phone_no, email 
            FROM user_uduit 
            WHERE phone_no = ? OR email = ?
            LIMIT 1
        `;
        const [duplicateRows] = await pool.execute(checkQuery, [phoneNo, email]);

        if (duplicateRows.length > 0) {
            const existingData = duplicateRows[0];
            let conflictField = '';

            if (existingData.phone_no === phoneNo) {
                conflictField = 'Nomor HP';
            } else if (existingData.email === email) {
                conflictField = 'Email';
            }

            return res.status(409).json({
                responseCode: "4090001",
                responseMessage: `Pendaftaran gagal. ${conflictField} ini sudah terdaftar.`
            });
        }

        const result = await postAccountCreation(req.body);

        if (result.status === 200 && result.data.responseCode === '2000600') {
            try {
                await saveRegistrationData(req.body, result.data);
            } catch (dbError) {
                console.error('API sukses, tetapi GAGAL menyimpan ke database:', dbError.message);
            }
        }

        res.status(result.status).json(result.data);
    } catch (error) {
        console.error('Error during account creation process:', error);
        const serverErrorResponse = { responseMessage: 'Internal Server Error' };
        res.status(500).json(serverErrorResponse);
    }
});

// ENDPOINT LAINNYA (TIDAK BERUBAH)
app.post('/api/account-inquiry', async (req, res) => {
    if (!req.body || !req.body.accountId) {
        return res.status(400).json({ responseMessage: 'accountId is required.' });
    }
    const result = await postAccountInquiry(req.body);
    res.status(result.status).json(result.data);
});

app.post('/api/account-profile', async (req, res) => {
    const { accountId } = req.body;
    if (!accountId) return res.status(400).json({ responseMessage: 'accountId is required.' });
    const result = await getAccountProfile(accountId);
    res.status(result.status).json(result.data);
});

app.post('/api/balance-inquiry', async (req, res) => {
    const { accountId } = req.body;
    if (!accountId) return res.status(400).json({ responseMessage: 'accountId is required.' });
    const result = await getBalanceInquiry(accountId);
    res.status(result.status).json(result.data);
});

app.post('/api/change-mpin', async (req, res) => {
    const { accountId, email, phoneNo } = req.body;
    if (!accountId || !email || !phoneNo) {
        return res.status(400).json({ responseMessage: 'accountId, email, and phoneNo are required.' });
    }
    const result = await postChangeMPIN(accountId, email, phoneNo);
    res.status(result.status).json(result.data);
});

app.post('/api/reset-mpin', async (req, res) => {
    const { accountId, referenceNo } = req.body;
    if (!accountId || !referenceNo) {
        return res.status(400).json({ responseMessage: 'accountId and referenceNo are required.' });
    }
    const result = await postResetMPIN(accountId, referenceNo);
    res.status(result.status).json(result.data);
});

app.post('/api/transaction-history', async (req, res) => {
    const { accountId, fromDateTime, toDateTime, pageId, lastTrxDate } = req.body;
    if (!accountId || !fromDateTime || !toDateTime) {
        return res.status(400).json({ responseMessage: 'accountId, fromDateTime, and toDateTime are required.' });
    }
    const result = await getTransactionHistory(accountId, fromDateTime, toDateTime, pageId, lastTrxDate);
    res.status(result.status).json(result.data);
});

app.post('/api/card-profile', async (req, res) => {
    const { accountId } = req.body;
    if (!accountId) return res.status(400).json({ responseMessage: 'accountId is required.' });
    const result = await getCardProfile(accountId);
    res.status(result.status).json(result.data);
});


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
        console.error('Server is running but token setup failed. Check the token values and private.pem.');
    }
    console.log('------------------------------');
    console.log(`Available Endpoints:`);
    console.log(`POST http://localhost:${port}/api/account-creation (B2B, Saves DB)`);
    console.log(`POST http://localhost:${port}/api/uduit/check-registration (DB Validation)`);
    console.log(`... and others.`);
});