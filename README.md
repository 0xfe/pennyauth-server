# pennyauth-server

A server-side pennyauth authenticator built on Google Cloud Functions.

## Production notes

- GCP Project: pennyauth
- Service account `pennyauth@appspot.gserviceaccount.com`
- Cloud function: `validateCaptcha`

## Setup and testing

Install the [Cloud Functions Emulator](https://cloud.google.com/functions/docs/emulator) to develop and test pennyauth-server.

```
# Install Cloud Functions NodeJS emulator
$ npm install -g @google-cloud/functions-emulator

# Start datastore emulator
$ gcloud beta emulators datastore start --no-store-on-disk --consistency 1.0

$ export DATASTORE_EMULATOR_HOST=localhost:8081
$ functions start

# Deploy to emulator and test
$ functions deploy validateCaptcha --trigger-http
$ functions call validateCaptcha --file=request.json
$ functions logs read

# Create key
$ functions call createAPIKey --data='{"origin": "http://localhost:8080"}'

# Create validate captcha
```

## Deploying to production

```
$ gcloud auth login mo@quid.works
$ gcloud config set project pennyauth
$ gcloud functions deploy createAPIKey --runtime nodejs8 --trigger-http
$ gcloud functions deploy validateCaptcha --runtime nodejs8 --trigger-http

# Update secrets
gcloud functions deploy createAPIKey --update-env-vars QUID_API_SECRET=ks-XXX
gcloud functions deploy validateCaptcha --update-env-vars QUID_API_SECRET=ks-XXX
```

## Debugging

Logs via `console.log` are written to the cloud function logs (and stackdriver in prod.)

```
$ gcloud functions call validateCaptcha --file=params.json
$ curl -X POST "https://us-central1-pennyauth.cloudfunctions.net/validateCaptcha" \
  -H "Content-Type:application/json" \
  --data '@params.json'

$ gcloud functions logs read
```
