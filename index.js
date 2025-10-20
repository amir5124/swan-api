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

const CLIENT_ID = '0199dc00-f2df-74b1-95e4-8664bdaaa9dd';
const CLIENT_SECRET = '425f8e4a-0f0c-474a-aa4f-64538f87bed4.0d.DIYVm+96QGa0mCg2X5JxRSG79BuHQJw+YGPV7aCuUIk=';
const BASE_URL = 'https://natsu-api-sandbox.smbpay.id';
const CLIENT_TOKEN_URL = `${BASE_URL}/oauth/token`;
const B2B_TOKEN_ENDPOINT = '/v2.0/access-token/b2b/';
const B2B_TOKEN_URL = `${BASE_URL}${B2B_TOKEN_ENDPOINT}`;

// PERBAIKAN: Mengembalikan trailing slash sesuai dokumentasi
const RELATIVE_PATH = '/cobrand-saving/v1.0/registration-account-creation/';

const CREATE_ACCOUNT_URL = `${BASE_URL}${RELATIVE_PATH}`;
const PRIVATE_KEY_PATH = './private.pem';


let clientAccessToken = null;
let b2bAccessToken = null;

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

const generateSymmetricSignature = (
    method,
    path,
    accessToken,
    payload,
    timestamp,
    secretKey
) => {
    let jsonString = stableStringify(payload);
    console.log("[SIGNATURE LOG] Stable Stringify Body:", jsonString);

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

    console.log(`[SIGNATURE LOG] Body Hash (SHA-256): ${hash}`);
    console.log(`[SIGNATURE LOG] String to Sign: ${stringToSign}`);
    console.log(`[SIGNATURE LOG] Signature (Base64): ${signature.substring(0, 30)}... (omitted)`);

    return { signature, stringToSign, hash, jsonString };
};

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

    console.log('\n--- LOG: GET CLIENT TOKEN REQUEST ---');
    console.log(`[REQUEST URL]: ${CLIENT_TOKEN_URL}`);
    console.log(`[REQUEST BODY]: ${payload}`);
    console.log('------------------------------------');

    try {
        const response = await axios.post(CLIENT_TOKEN_URL, payload, { headers });
        clientAccessToken = response.data.access_token;
        console.log('✅ Token Klien berhasil didapatkan.');
        console.log(`[RESPONSE TOKEN]: ${clientAccessToken.substring(0, 15)}... (omitted)`);
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

        console.log('\n--- LOG: GET B2B TOKEN REQUEST (Asymmetric Signature) ---');
        console.log(`[REQUEST URL]: ${B2B_TOKEN_URL}`);
        console.log(`[STRING TO SIGN]: ${stringToSign}`);
        console.log(`[REQUEST HEADER] X-TIMESTAMP: ${srvTimestamp}`);
        console.log(`[REQUEST HEADER] X-SIGNATURE: ${signature.substring(0, 30)}... (omitted)`);
        console.log('---------------------------------------------------------');

        const response = await axios.post(B2B_TOKEN_URL, requestBody, { headers });
        b2bAccessToken = response.data.accessToken;

        console.log(`✅ Token B2B berhasil didapatkan.`);
        console.log(`[RESPONSE TOKEN]: ${b2bAccessToken.substring(0, 15)}... (omitted)`);
        console.log(`[RESPONSE BODY]: ${JSON.stringify(response.data)}`);

        return b2bAccessToken;
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.error(`❌ File Kunci Privat tidak ditemukan di ${PRIVATE_KEY_PATH}.`);
        } else if (error.response) {
            console.error(`❌ Gagal ambil token B2B! Server: ${error.response.status}`);
            console.error(`[ERROR RESPONSE BODY]: ${JSON.stringify(error.response.data)}`);
        } else {
            console.error(`❌ Gagal ambil token B2B! Error: ${error.message}`);
        }
        return null;
    }
};

const createAccount = async (payload) => {
    const httpMethod = 'POST';
    const relativePath = RELATIVE_PATH;

    if (!b2bAccessToken) {
        return { status: 503, data: { pesan: 'B2B Token not available. Please initialize the server.' } };
    }

    const srvTimestamp = momentTimezone().tz('Asia/Jakarta').format('YYYY-MM-DDTHH:mm:ss') + '+07:00';

    // PERBAIKAN: Mengubah partnerImage menjadi URL valid/null sesuai hasil troubleshooting sebelumnya
    const requestBodyObj = payload || {
        "referenceNo": shortid.generate(),
        "phoneNo": "08123456789",
        "email": "adit@smbpay.id",
        "additionalInfo": {
            "config": {
                "productCode": "60",
                "callbackUrl": "https://your-callback-url.com/status",
                "partnerInfo": {
                    "partnerName": "PartnerName",
                    "partnerImage": "https://dummyimage.com/400x400/000/fff" // Menggunakan placeholder URL
                },
                "redirectUrl": {
                    "successUrl": "https://your-success-url.com",
                    "failedUrl": "https://your-failed-url.com"
                }
            },
            "customerData": {
                "idNumber": "123445353627272",
                "sourceOfFundCode": "02",
                "purposeOfFundCode": "02",
                "estimatedWithdrawCode": "01",
                "estimatedDepositCode": "01",
                "estimatedDepositAmount": "500000.00",
                "estimatedWithdrawAmount": "500000.00"
            },
            "imageKtp": ""
        }
    };

    console.log('\n--- LOG: CREATE ACCOUNT REQUEST (Symmetric Signature) ---');
    console.log(`[REQUEST URL]: ${CREATE_ACCOUNT_URL}`);
    console.log(`[RELATIVE PATH USED FOR SIGNATURE]: ${relativePath}`); // Log path untuk verifikasi

    try {
        const { signature, jsonString } = generateSymmetricSignature(
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
            'Content-Type': 'application/json',
        };

        console.log('\n[REQUEST HEADERS]:');
        console.log(`  X-TIMESTAMP: ${srvTimestamp}`);
        console.log(`  X-SIGNATURE: ${signature.substring(0, 30)}... (omitted)`);
        console.log(`  Authorization: Bearer ${b2bAccessToken.substring(0, 15)}... (omitted)`);
        console.log(`\n[REQUEST BODY (JSON)]: ${jsonString}`);
        console.log('-------------------------------------------------------');

        const response = await axios.post(CREATE_ACCOUNT_URL, jsonString, { headers });

        console.log('\n--- LOG: CREATE ACCOUNT RESPONSE ---');
        console.log(`[RESPONSE STATUS]: ${response.status}`);
        console.log(`[RESPONSE BODY]: ${JSON.stringify(response.data)}`);
        console.log('------------------------------------');

        return { status: response.status, data: response.data };
    } catch (error) {
        if (error.response) {
            console.error('\n--- LOG: CREATE ACCOUNT ERROR RESPONSE ---');
            console.error(`❌ Gagal membuat akun! Server: ${error.response.status}`);
            console.error(`[ERROR RESPONSE BODY]: ${JSON.stringify(error.response.data)}`);
            console.error('------------------------------------------');
            return { status: error.response.status, data: error.response.data };
        } else {
            console.error(`❌ Gagal membuat akun! Error jaringan/lain: ${error.message}`);
            return { status: 500, data: { pesan: error.message } };
        }
    }
};

app.use(express.json());

app.post('/api/create-account', async (req, res) => {
    const result = await createAccount(req.body);
    res.status(result.status).json(result.data);
});

app.listen(port, async () => {
    console.log(`Server berjalan di http://localhost:${port}`);

    console.log('\n====================================');
    console.log('       INISIATIF TOKEN CLIENT       ');
    console.log('====================================');
    const tokenKlien = await getClientToken();

    if (tokenKlien) {
        console.log('\n====================================');
        console.log('        INISIATIF TOKEN B2B         ');
        console.log('====================================');
        await getB2BToken();
    }

    console.log('\n✅ Initialization complete. Access API via POST http://localhost:3000/api/create-account');
});