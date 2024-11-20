# Webhook Integration Guide

## Overview

Webhooks allow you to receive real-time updates for specific events, enabling you to integrate our platform seamlessly into your workflows.

---

## Setup

### Enabling Webhooks

1. Navigate to **API -> Webhooks** in QGEN.
2. Click **ADD**.
3. Configure the following:
   - **Endpoint**: The HTTPS URL where the webhook will send event data.
   - **Events**: Select one or more events that will trigger the webhook.
4. Save your webhook and copy the provided `secret_key`. This key will be used to verify the authenticity of incoming webhook requests.

---

## Supported Events

Below are the available events that can be configured for a webhook:

| Event Type                         | Description                                 |
| ---------------------------------- | ------------------------------------------- |
| `cfm_case_created_event`           | Triggered when a new case is created.       |
| `cfm_entity_created_event`         | Triggered when a new entity is created.     |
| `cfm_entity_rejected_terms_event`  | Triggered when terms are rejected.          |
| `cfm_journey_completed_event`      | Triggered when a journey is completed.      |
| `cfm_user_geo_blocked_event`       | Triggered when a user is geo-blocked.       |
| `cfm_fast_fail_inconclusive_event` | Triggered for fast-fail inconclusive cases. |
| `cfm_kyc_completed_event`          | Triggered when KYC is completed.            |

---

## Security and Verification

Each webhook request is signed using HMAC for authenticity. Use the provided `secret_key` to verify the signature in your backend.

### Request Headers

| Header Name                   | Description                                |
| ----------------------------- | ------------------------------------------ |
| `SignatureHeaderKey`          | The HMAC signature for the request.        |
| `SignatureHeaderTimestampKey` | The timestamp when the request was signed. |
| `SignatureHeaderEndpoint`     | The endpoint URL used for signing.         |

### Signing Process

Before sending the request, we compute the HMAC signature as follows:

1. **Data to Sign**: Concatenate the following:
   - Timestamp (`SignatureHeaderTimestampKey`)
   - HTTP Method (e.g., `POST`)
   - Endpoint (URL path)
   - JSON payload (ordered by key).
2. **Generate Signature**: Compute the HMAC using SHA256 and the webhook's `secret_key`.

Example signing process in Go:

```go
func sign(method, endpoint string, request []byte) (string, string) {
    timeStamp := c.getTimestamp()
    data := []byte(timeStamp + method + endpoint)
    data = append(data, request...)
    return timeStamp, commonutils.ComputeHMAC256HEX(string(data), c.secretKey)
}
```

Example checking signature process in Js:

```js
const crypto = require("crypto");

function validateWebhook(headers, body, secretKey) {
  const signature = headers["SignatureHeaderKey"];
  const timestamp = headers["SignatureHeaderTimestampKey"];
  const endpoint = headers["SignatureHeaderEndpoint"];

  if (!signature || !timestamp || !endpoint) {
    throw new Error("Missing required headers");
  }

  // Reconstruct the data to sign
  const sortedBody = JSON.stringify(
    Object.keys(body)
      .sort()
      .reduce((obj, key) => {
        obj[key] = body[key];
        return obj;
      }, {})
  );

  const data = timestamp + "POST" + endpoint + sortedBody;

  // Compute HMAC signature
  const computedSignature = crypto
    .createHmac("sha256", secretKey)
    .update(data)
    .digest("hex");

  // Compare signatures
  if (signature !== computedSignature) {
    throw new Error("Invalid HMAC signature");
  }

  return true;
}
```
