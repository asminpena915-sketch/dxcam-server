const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use((req, res, next) => {
    console.log('REQUEST: ' + req.method + ' ' + req.url + ' from ' + req.ip);
    next();
});

// === CONFIGURACIÓN ===
const ADMIN_TOKEN = 'dxcam-admin-998877';
const HMAC_SECRET = 'dxcam-vrf-2024-secret-key-change-this';
const MONGO_URL = 'mongodb+srv://asminpena915_db_user:bxOn7QVwski85IVk@cluster0.axiytje.mongodb.net/?appName=Cluster0';

// === CONEXIÓN A BASE DE DATOS ===
mongoose.connect(MONGO_URL)
    .then(() => console.log('Base de datos conectada'))
    .catch(err => console.error('Error BD:', err));

// === MODELO DE KEY ===
const Key = mongoose.model('Key', {
    key: String,
    expiresAt: Date,
    deviceId: String,
    deviceModel: String,
    activated: Boolean,
    createdAt: { type: Date, default: Date.now }
});

// === FUNCIÓN DE FIRMA HMAC ===
function hmacSign(valid, remainingMs) {
    const data = valid + ':' + remainingMs;
    return crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex');
}

// === FUNCIÓN GENERAR TOKEN DE ACTIVACIÓN ===
function generateActivationToken(key, deviceId) {
    const timestamp = Date.now();
    const data = key + ':' + deviceId + ':' + timestamp;
    return crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex');
}

// === CREAR KEY (SOLO ADMIN) ===
app.get('/api/activate', async (req, res) => {
    try {
        const { key, days, token } = req.query;

        if (!token || token !== ADMIN_TOKEN) {
            return res.status(401).json({ error: 'unauthorized', message: 'Invalid admin token' });
        }

        if (!key || !days || isNaN(parseInt(days))) {
            return res.status(400).json({ error: 'bad_request', message: 'Missing key or days' });
        }

        const daysInt = parseInt(days);
        if (daysInt < 1 || daysInt > 3650) {
            return res.status(400).json({ error: 'bad_request', message: 'Days must be 1-3650' });
        }

        const expiresAt = new Date(Date.now() + (daysInt * 24 * 60 * 60 * 1000));

        const existingKey = await Key.findOne({ key: key });
        if (existingKey) {
            existingKey.expiresAt = expiresAt;
            existingKey.deviceId = null;
            existingKey.activated = false;
            await existingKey.save();
        } else {
            await Key.create({
                key: key,
                expiresAt: expiresAt,
                deviceId: null,
                activated: false
            });
        }

        res.json({
            valid: true,
            key: key,
            expires: expiresAt.toISOString(),
            remaining_days: daysInt
        });
    } catch (err) {
        res.status(500).json({ error: 'server_error' });
    }
});

// === LISTAR KEYS (SOLO ADMIN) ===
app.get('/api/keys', async (req, res) => {
    try {
        const { token } = req.query;

        if (!token || token !== ADMIN_TOKEN) {
            return res.status(401).json({ error: 'unauthorized' });
        }

        const allKeys = await Key.find({});
        const keyList = allKeys.map(k => ({
            key: k.key,
            expires: k.expiresAt.toISOString(),
            deviceId: k.deviceId,
            activated: k.activated,
            remaining_days: Math.max(0, Math.ceil((k.expiresAt - Date.now()) / (24 * 60 * 60 * 1000)))
        }));

        res.json({ keys: keyList });
    } catch (err) {
        res.status(500).json({ error: 'server_error' });
    }
});

// === VERIFICAR KEY (CLIENTE) ===
app.post('/api/verify', async (req, res) => {
    try {
        const { key, android_id, device_model } = req.body;

        if (!key || !android_id) {
            return res.status(400).json({ valid: false, error: 'Missing key or android_id' });
        }

        const keyData = await Key.findOne({ key: key });

        if (!keyData) {
            return res.json({ valid: false, error: 'Key not found' });
        }

        if (Date.now() > keyData.expiresAt) {
            return res.json({ valid: false, error: 'Key expired' });
        }

        if (keyData.deviceId && keyData.deviceId !== android_id) {
            return res.json({ valid: false, error: 'Key already used on another device' });
        }

        if (!keyData.deviceId) {
            keyData.deviceId = android_id;
            keyData.deviceModel = device_model || 'unknown';
            keyData.activated = true;
            await keyData.save();
        }

        const remainingMs = keyData.expiresAt - Date.now();
        const sig = hmacSign(true, remainingMs);
        const activationToken = generateActivationToken(key, keyData.deviceId);

        res.json({
            valid: true,
            remaining_ms: remainingMs,
            sig: sig,
            token: activationToken
        });
    } catch (err) {
        res.status(500).json({ valid: false, error: 'server_error' });
    }
});

// === CHEQUEAR KEY (CLIENTE) ===
app.get('/api/check/:key', async (req, res) => {
    try {
        const { key } = req.params;

        const keyData = await Key.findOne({ key: key });

        if (!keyData) {
            return res.json({ valid: false, error: 'Key not found' });
        }

        if (Date.now() > keyData.expiresAt) {
            return res.json({ valid: false });
        }

        const remainingMs = keyData.expiresAt - Date.now();
        const sig = hmacSign(true, remainingMs);
        const activationToken = generateActivationToken(key, keyData.deviceId);

        res.json({
            valid: true,
            remaining_ms: remainingMs,
            sig: sig,
            token: activationToken
        });
    } catch (err) {
        res.status(500).json({ valid: false, error: 'server_error' });
    }
});

// === ELIMINAR KEY (SOLO ADMIN) ===
app.get('/api/delete', async (req, res) => {
    try {
        const { key, token } = req.query;

        if (!token || token !== ADMIN_TOKEN) {
            return res.status(401).json({ error: 'unauthorized', message: 'Invalid admin token' });
        }

        if (!key) {
            return res.status(400).json({ error: 'bad_request', message: 'Missing key' });
        }

        const deleted = await Key.findOneAndDelete({ key: key });

        if (!deleted) {
            return res.json({ success: false, message: 'Key not found' });
        }

        res.json({ success: true, message: 'Key deleted permanently', key: key });
    } catch (err) {
        res.status(500).json({ error: 'server_error' });
    }
});

// === LIBERAR DISPOSITIVO (SOLO ADMIN) ===
app.get('/api/unbind', async (req, res) => {
    try {
        const { key, token } = req.query;

        if (!token || token !== ADMIN_TOKEN) {
            return res.status(401).json({ error: 'unauthorized', message: 'Invalid admin token' });
        }

        if (!key) {
            return res.status(400).json({ error: 'bad_request', message: 'Missing key' });
        }

        const keyData = await Key.findOne({ key: key });

        if (!keyData) {
            return res.json({ success: false, message: 'Key not found' });
        }

        keyData.deviceId = null;
        keyData.deviceModel = null;
        keyData.activated = false;
        await keyData.save();

        res.json({ success: true, message: 'Device unbound, key is free', key: key });
    } catch (err) {
        res.status(500).json({ error: 'server_error' });
    }
});

// === VER INFO DE UNA KEY (SOLO ADMIN) ===
app.get('/api/info', async (req, res) => {
    try {
        const { key, token } = req.query;

        if (!token || token !== ADMIN_TOKEN) {
            return res.status(401).json({ error: 'unauthorized', message: 'Invalid admin token' });
        }

        if (!key) {
            return res.status(400).json({ error: 'bad_request', message: 'Missing key' });
        }

        const keyData = await Key.findOne({ key: key });

        if (!keyData) {
            return res.json({ found: false, message: 'Key not found' });
        }

        res.json({
            found: true,
            key: keyData.key,
            expires: keyData.expiresAt.toISOString(),
            deviceId: keyData.deviceId,
            deviceModel: keyData.deviceModel,
            activated: keyData.activated,
            remaining_days: Math.max(0, Math.ceil((keyData.expiresAt - Date.now()) / (24 * 60 * 60 * 1000)))
        });
    } catch (err) {
        res.status(500).json({ error: 'server_error' });
    }
});

// === HEALTH CHECK ===
app.get('/', (req, res) => {
    res.json({ status: 'ok', server: 'DXCam License Server v3' });
});

// === INICIAR ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('DXCam License Server v3 running on port ' + PORT);
});
