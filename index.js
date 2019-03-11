const crypto = require('crypto');
const process = require('process');
const { Datastore } = require('@google-cloud/datastore');
const H = require('./helpers');

// Test secrets
const QUID_API_SECRET = 'ks-WCUIO9CE2M41IXAA87HTWHQI2YW2YSX6';

const datastore = new Datastore({ projectId: process.env.PROJECT_ID || 'pennyauth' });

function createAPIKey(origin) {
  const apiKey = `k-${crypto.pseudoRandomBytes(16).toString('hex')}`;
  const apiSecret = `s-${crypto.pseudoRandomBytes(16).toString('hex')}`;

  const hashedSecret = crypto
    .createHash('SHA256')
    .update(apiSecret)
    .digest('hex');

  const keyEntity = {
    key: datastore.key(['t-Key', apiKey]),
    data: {
      origin,
      secret: hashedSecret,
    },
  };

  // Saves the entity
  H.log(`Saving ${keyEntity.key.name}: ${keyEntity.data.origin}`);
  return datastore.insert(keyEntity).then(() => ({ apiKey, apiSecret }));
}

async function lookupAPIKey(apiKey, origin) {
  const key = datastore.key(['t-Key', apiKey]);
  const entity = await datastore.get(key);

  if (!entity) {
    return H.makeError('NOTFOUND', 'Invalid API key');
  }

  if (entity[0].origin !== origin) {
    return H.makeError('PERMISSION_DENIED', 'Invalid origin');
  }

  return H.makeSuccess(entity[0]);
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
  H.log(`${req.method}:${origin} ${req.originalUrl}`);

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
    return H.sendError(res, 403, 'SERVER_ERROR', `Bad request method: ${req.method}`);
  }

  return true;
}

exports.validateCaptcha = async (req, res) => {
  if (!processCORS(req, res)) return {};

  // Body is already parsed (as JSON or whatever the content-type is) by cloud functions.
  const params = req.body;

  const origin = req.headers.origin || req.headers.referer;
  const result = await lookupAPIKey(params.apiKey, origin);
  if (!result.success) {
    return H.send(res, 401, result);
  }

  if (!validatePayment(params.receipt)) {
    return H.sendError(res, 401, 'VALIDATION_FAILED', 'Could not verify payment');
  }

  const response = {
    id: crypto.pseudoRandomBytes(32).toString('hex'),
    unixTime: Math.floor(new Date() / 1000),
    origin: params.origin,
    apiKey: params.apiKey,
  };

  // Calculate signature of payload using secret
  const payload = [result.id, result.unixTime, result.origin, result.apiKey].join(',');
  response.sig = crypto
    .createHmac('SHA256', result.data.secret)
    .update(payload)
    .digest('base64');

  return H.sendSuccess(res, response);
};

exports.createAPIKey = async (req, res) => {
  if (!processCORS(req, res)) return;

  // Body is already parsed (as JSON or whatever the content-type is) by cloud functions.
  const params = req.body;

  createAPIKey(params.origin)
    .then((result) => {
      H.sendSuccess(res, result);
    })
    .catch((e) => {
      H.logError(e);
      H.sendError(res, e);
    });
};
