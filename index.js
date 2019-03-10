const crypto = require('crypto');
const { Datastore } = require('@google-cloud/datastore');

const QUID_API_SECRET = 'ks-WCUIO9CE2M41IXAA87HTWHQI2YW2YSX6';

const secret = crypto
  .createHash('SHA256')
  .update(QUID_API_SECRET)
  .digest('base64');

function validatePayment(receipt) {
  if (!receipt) return false;
  const payload = [receipt.id, receipt.userHash, receipt.merchantID, receipt.productID, receipt.currency, receipt.amount, receipt.tsUnix].join(',');

  // Calculate signature of payload using secret
  const sig = crypto
    .createHmac('SHA256', secret)
    .update(payload)
    .digest('base64');

  return sig === receipt.sig;
}

// Imports the Google Cloud client library

let id = 13;

async function quickStart() {
  // Your Google Cloud Platform project ID
  const projectId = 'pennyauth';

  // Creates a client
  const datastore = new Datastore({
    projectId,
  });

  // Prepares the new entity
  const task = {
    key: datastore.key(['t-Task', `task-${id}`]),
    data: {
      description: 'Buy milk',
    },
  };

  // Saves the entity
  await datastore.save(task);
  console.log(`Saved ${task.key.name}: ${task.data.description}`);
  id += 1;
}

// Main Cloud Function handler. Triggered via HTTP.
exports.validateCaptcha = async (req, res) => {
  // CORS setup
  const origin = req.headers.origin || req.headers.referer;

  quickStart().catch(console.error);

  // Send response to OPTIONS requests
  res.set('Access-Control-Allow-Methods', 'OPTIONS,POST');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  res.set('Access-Control-Max-Age', '3600');
  res.set('Access-Control-Allow-Credentials', 'true');
  res.set('Access-Control-Allow-Origin', origin);

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }

  if (req.method !== 'POST') {
    res.status(403).send(`Bad request method: ${req.method}`);
  }

  // Body is already parsed (as JSON or whatever the content-type is) by cloud functions.
  const params = req.body;
  if (!validatePayment(params.receipt)) {
    res.status(401).send('{"success": false, "code": "VALIDATION_FAILED"}');
    return;
  }

  res.status(200).send(`{"success": true, "params": ${JSON.stringify(params)}}`);
};
