const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const momentTimezone = require('moment-timezone');
const fs = require('fs');
const { URLSearchParams } = require('url');
const shortid = require('shortid');
const stableStringify = require('json-stable-stringify');

const app = express();
const port = 3000;

// --- KONSTANTA API ---
const CLIENT_ID = '0199dc00-f2df-74b1-95e4-8664bdaaa9dd';
const CLIENT_SECRET = '425f8e4a-0f0c-474a-aa4f-64538f87bed4.0d.DIYVm+96QGa0mCg2X5JxRSG79BuHQJw+YGPV7aCuUIk=';
const BASE_URL = 'https://natsu-api-sandbox.smbpay.id';
const CLIENT_TOKEN_URL = `${BASE_URL}/oauth/token`;
const B2B_TOKEN_ENDPOINT = '/v2.0/access-token/b2b/';
const B2B_TOKEN_URL = `${BASE_URL}${B2B_TOKEN_ENDPOINT}`;
const RELATIVE_PATH = '/cobrand-saving/v1.0/registration-account-creation/';
const CREATE_ACCOUNT_URL = `${BASE_URL}${RELATIVE_PATH}`;
const PRIVATE_KEY_PATH = './private.pem';

let clientAccessToken = null;
let b2bAccessToken = null;

// --- FUNGSI SIGNATURE ---

const createAsymmetricSignature = (srvTimestamp, clientId, privateKeyPath) => {
    try {
        const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
        const stringToSign = `${clientId}|${srvTimestamp}`;
        const signer = crypto.createSign('RSA-SHA256');
        signer.update(stringToSign);
        const signature = signer.sign(privateKey, 'base64');
        return { signature, stringToSign };
    } catch (e) {
        console.error(`Error membaca atau menandatangani kunci privat: ${e.message}`);
        throw new Error('Asymmetric signature creation failed.');
    }
};

const createSymmetricSignature = (
    method,
    relativePath,
    accessToken,
    payload,
    timestamp,
    clientSecret
) => {
    // 1. Minify & Sort Payload
    let jsonString = stableStringify(payload);

    // 2. Hash Body: SHA-256, Hex, Lowercase
    const hash = crypto.createHash('sha256').update(jsonString).digest('hex').toLowerCase();

    // 3. String to Sign: $method:$path:$token:$hash:$timestamp
    const stringToSign = [
        method,
        relativePath,
        accessToken,
        hash,
        timestamp
    ].join(':');

    // 4. Signature: HMAC SHA-512 dengan CLIENT_SECRET
    const signature = crypto.createHmac('sha512', clientSecret)
        .update(stringToSign)
        .digest('base64');

    return { signature, stringToSign, hash, jsonString }; // Mengembalikan jsonString untuk log
};

// --- FUNGSI TOKEN & API ---

const getClientToken = async () => {
    const data = {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET
    };
    const payload = new URLSearchParams(data).toString();
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    };

    try {
        const response = await axios.post(CLIENT_TOKEN_URL, payload, { headers });
        clientAccessToken = response.data.access_token;
        console.log('✅ Token Klien berhasil didapatkan.');
        return clientAccessToken;
    } catch (error) {
        if (error.response) {
            console.error('❌ Gagal ambil token Klien! Server:', error.response.status, error.response.data);
        } else {
            console.error('❌ Gagal ambil token Klien! Jaringan/Lain:', error.message);
        }
        return null;
    }
};

const getB2BToken = async () => {
    if (!clientAccessToken) return null;

    const srvTimestamp = momentTimezone().tz('Asia/Jakarta').format('YYYY-MM-DDTHH:mm:ss') + '+07:00';

    try {
        const { signature, stringToSign } = createAsymmetricSignature(srvTimestamp, CLIENT_ID, PRIVATE_KEY_PATH);

        const requestBody = JSON.stringify({
            "grantType": "client_credentials",
            "additionalInfo": {}
        });

        const headers = {
            'X-TIMESTAMP': srvTimestamp,
            'X-SIGNATURE': signature,
            'X-CLIENT-KEY': CLIENT_ID,
            'Authorization': `Bearer ${clientAccessToken}`,
            'Content-Type': 'application/json'
        };

        // --- LOG ASYMMETRIC SIGNATURE (B2B Token) ---
        console.log('\n--- LOG B2B TOKEN REQUEST (Asymmetric Signature) ---');
        console.log(`[REQUEST BODY]: ${requestBody}`);
        console.log(`[STRING TO SIGN]: ${stringToSign}`);
        console.log(`[REQUEST HEADER] X-TIMESTAMP: ${srvTimestamp}`);
        console.log(`[REQUEST HEADER] X-SIGNATURE: ${signature}`);
        console.log(`[REQUEST URL]: ${B2B_TOKEN_URL}`);
        console.log('--------------------------------------------------');

        const response = await axios.post(B2B_TOKEN_URL, requestBody, { headers });
        b2bAccessToken = response.data.accessToken;
        console.log(`✅ Token B2B berhasil didapatkan.`);
        return b2bAccessToken;
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.error(`❌ File Kunci Privat tidak ditemukan di ${PRIVATE_KEY_PATH}.`);
        } else if (error.response) {
            console.error(`❌ Gagal ambil token B2B! Server: ${error.response.status}`);
        } else {
            console.error(`❌ Gagal ambil token B2B! Error: ${error.message}`);
        }
        return null;
    }
};

const createAccount = async () => {
    const httpMethod = 'POST';
    const relativePath = RELATIVE_PATH;

    if (!b2bAccessToken) {
        return { status: 503, data: { pesan: 'Token B2B not available. Please initialize the server.' } };
    }

    const srvTimestamp = momentTimezone().tz('Asia/Jakarta').format('YYYY-MM-DDTHH:mm:ss') + '+07:00';

    // Payload (diasumsikan statis untuk contoh ini, dalam aplikasi nyata ambil dari req.body)
    const requestBodyObj = {
        "referenceNo": shortid.generate(),
        "phoneNo": "08123456789",
        "email": "adit@smbpay.id",
        "additionalInfo": {
            "config": {
                "productCode": "60",
                "callbackUrl": "https://your-callback-url.com/status",
                "partnerInfo": {
                    "partnerName": "PartnerName",
                    "partnerImage": ""
                },
                "redirectUrl": {
                    "successUrl": "https://your-success-url.com",
                    "failedUrl": "https://your-failed-url.com"
                }
            },
            "customerData": {
                "idNumber": "1234567890123456",
                "sourceOfFundCode": "02",
                "purposeOfFundCode": "02",
                "estimatedWithdrawCode": "01",
                "estimatedDepositCode": "01",
                "estimatedDepositAmount": "5000000",
                "estimatedWithdrawAmount": "5000000"
            },
            "imageKtp": ""
        }
    };

    try {
        const { signature, stringToSign, hash, jsonString } = createSymmetricSignature(
            httpMethod,
            relativePath,
            b2bAccessToken,
            requestBodyObj,
            srvTimestamp,
            CLIENT_SECRET
        );

        const headers = {
            'X-TIMESTAMP': srvTimestamp,
            'X-SIGNATURE': signature,
            'X-CLIENT-KEY': CLIENT_ID,
            'Authorization': `Bearer ${b2bAccessToken}`,
            'Content-Type': 'application/json'
        };

        // --- LOG SYMMETRIC SIGNATURE (Create Account) ---
        console.log('\n--- LOG CREATE ACCOUNT REQUEST (Symmetric Signature) ---');
        console.log(`[REQUEST BODY (Stable Stringify)]: ${jsonString}`);
        console.log(`[BODY HASH (SHA-256)]: ${hash}`);
        console.log(`[STRING TO SIGN]: ${stringToSign}`);
        console.log(`[REQUEST HEADER] X-TIMESTAMP: ${srvTimestamp}`);
        console.log(`[REQUEST HEADER] X-SIGNATURE: ${signature}`);
        console.log(`[REQUEST URL]: ${CREATE_ACCOUNT_URL}`);
        console.log('-------------------------------------------------------');

        // Mengirim request ke API eksternal
        const response = await axios.post(CREATE_ACCOUNT_URL, jsonString, { headers });
        console.log(`[RESPONSE CREATE ACCOUNT] Status: ${response.status}`);
        return { status: response.status, data: response.data };
    } catch (error) {
        if (error.response) {
            console.error(`❌ Gagal membuat akun! Server: ${error.response.status} ${JSON.stringify(error.response.data)}`);
            return { status: error.response.status, data: error.response.data };
        } else {
            console.error(`❌ Gagal membuat akun! Error jaringan/lain: ${error.message}`);
            return { status: 500, data: { pesan: error.message } };
        }
    }
};

// --- EXPRESS ROUTE ---

app.use(express.json());

app.post('/api/create-account', async (req, res) => {
    // Catatan: Payload statis di dalam createAccount() diabaikan,
    // dalam kasus nyata Anda akan meneruskan req.body ke fungsi createAccount.
    const result = await createAccount();
    res.status(result.status).json(result.data);
});

// --- START SERVER ---

app.listen(port, async () => {
    console.log(`Server berjalan di http://localhost:${port}`);

    const tokenKlien = await getClientToken();
    if (tokenKlien) {
        await getB2BToken();
    }
    console.log('\n✅ Initialization complete. Access API via POST http://localhost:3000/api/create-account');
});