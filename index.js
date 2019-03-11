const crypto = require('crypto');
const process = require('process');

const { Datastore } = require('@google-cloud/datastore');

// Test secrets
const QUID_API_SECRET = 'ks-WCUIO9CE2M41IXAA87HTWHQI2YW2YSX6';
const PENNYAUTH_SHARED_SECRET = 's00per secure';
const VERSION = '0.00';

const datastore = new Datastore({ projectId: process.env.PROJECT_ID || 'pennyauth' });

function log(...args) {
  // eslint-disable-next-line
  console.log(VERSION, ...args);
}

function logError(...args) {
  // eslint-disable-next-line
  console.error(VERSION, ...args);
}

async function createAPIKey(origin) {
  const apiKey = crypto.pseudoRandomBytes(48).toString('hex');
  const apiSecret = crypto.pseudoRandomBytes(48).toString('hex');

  const hashedSecret = crypto
    .createHash('SHA256')
    .update(apiSecret)
    .digest('hex');

  const keyEntity = {
    key: datastore.key(['t-Key', `k-${apiKey}`]),
    data: {
      origin,
      secret: hashedSecret,
    },
  };

  // Saves the entity
  await datastore.save(keyEntity);
  log(`Saved ${keyEntity.key.name}: ${keyEntity.data.origin}`);
}

function validatePayment(receipt) {
  if (!receipt) return false;
  const payload = [receipt.id, receipt.userHash, receipt.merchantID, receipt.productID, receipt.currency, receipt.amount, receipt.tsUnix].join(',');

  // Hash secret
  const secret = crypto
    .createHash('SHA256')
    .update(process.env.QUID_API_SECRET || QUID_API_SECRET)
    .digest('base64');

  // Calculate signature of payload using secret
  const sig = crypto
    .createHmac('SHA256', secret)
    .update(payload)
    .digest('base64');

  return sig === receipt.sig;
}

async function processCORS(req, res) {
  // CORS setup
  const origin = req.headers.origin || req.headers.referer;

  // Send response to OPTIONS requests
  res.set('Access-Control-Allow-Methods', 'OPTIONS,POST');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  res.set('Access-Control-Max-Age', '3600');
  res.set('Access-Control-Allow-Credentials', 'true');
  res.set('Access-Control-Allow-Origin', origin);

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return false;
  }

  if (req.method !== 'POST') {
    res.status(403).send(`Bad request method: ${req.method}`);
    return false;
  }

  return true;
}

exports.validateCaptcha = async (req, res) => {
  if (!processCORS(req, res)) return;

  // Body is already parsed (as JSON or whatever the content-type is) by cloud functions.
  const params = req.body;
  if (!validatePayment(params.receipt)) {
    res.status(401).send('{"success": false, "code": "VALIDATION_FAILED"}');
    return;
  }

  const result = {
    id: crypto.pseudoRandomBytes(48).toString('hex'),
    unixTime: Math.floor(new Date() / 1000),
    origin: params.origin,
    apiKey: params.apiKey,
  };

  // Calculate signature of payload using secret
  const payload = [result.id, result.unixTime, result.origin, result.apiKey].join(',');
  result.sig = crypto
    .createHmac('SHA256', PENNYAUTH_SHARED_SECRET)
    .update(payload)
    .digest('base64');

  res.status(200).send(`{"success": true, "data": ${JSON.stringify(result)}}`);
};

exports.createAPIKey = async (req, res) => {
  if (!processCORS(req, res)) return;

  // Body is already parsed (as JSON or whatever the content-type is) by cloud functions.
  const params = req.body;

  createAPIKey(params.origin)
    .then(() => {
      res.status(200).send(`{"success": true, "params": ${JSON.stringify(params)}}`);
    })
    .catch((e) => {
      logError(e);
      res.status(500).send({}`"success": false, "error": "${e}"}`);
    });
};
