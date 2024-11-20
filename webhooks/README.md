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

| Header Name              | Description                                |
| ------------------------ | ------------------------------------------ |
| `X-App-Access-Sig`       | The HMAC signature for the request.        |
| `X-App-Access-Timestamp` | The timestamp when the request was signed. |
| `X-App-Access-Endpoint`  | The endpoint URL used for signing.         |

### Signing Process

Before sending the request, we compute the HMAC signature as follows:

1. **Data to Sign**: Concatenate the following:
   - Timestamp (`X-App-Access-Timestamp`)
   - HTTP Method (e.g., `POST`)
   - Endpoint (`X-App-Access-Endpoint`)
   - JSON payload (ordered by key).
2. **Generate Signature**: Compute the HMAC using SHA256 and the webhook's `secret_key`.
3. **Check signature**: Compare your signature generated with the header `X-App-Access-Sig`

Example signing process in Go:

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Constants for headers
const (
	SignatureHeaderKey          = "X-App-Access-Sig"
	SignatureHeaderTimestampKey = "X-App-Access-Timestamp"
	SignatureHeaderEndpoint     = "X-App-Access-Endpoint"
)

// ComputeHMAC256HEX computes an HMAC SHA256 signature and returns it as a hex string.
func computeHMAC256HEX(content, hashKey string) string {
	h := hmac.New(sha256.New, []byte(hashKey))
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

// Generate a signature for the request
func sign(method, endpoint string, request []byte, secretKey string) (string, string) {
	timeStamp := fmt.Sprintf("%d", time.Now().Unix())
	data := []byte(timeStamp + method + endpoint)
	data = append(data, request...)
	signature := computeHMAC256HEX(string(data), secretKey)
	return timeStamp, signature
}

// MakeRequest sends a POST request with a signed header
func makeRequest(endpoint string, request interface{}, secretKey string) (*int, *string, error) {
	method := http.MethodPost

	// Marshal the request into JSON
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshalling request: %w", err)
	}


  // Order the request by key
	o := orderedmap.New()
	unMarshalErr := json.Unmarshal(requestJSON, &o)
	if unMarshalErr != nil {
		return nil, nil, fmt.Errorf("error unmarshalling request object: %w", unMarshalErr)
	}

   // Sorting the request by keys
	o.SortKeys(sort.Strings)
	orderedBytes, orderedBytesErr := json.Marshal(o)
	if orderedBytesErr != nil {
		return nil, nil, fmt.Errorf("error marshalling ordered request object: %w", orderedBytesErr)
	}

	// Generate signature
	timeStamp, signature := sign(method, endpoint, orderedBytes, secretKey)

	// Create HTTP request
	httpRequest, err := http.NewRequest(method, endpoint, bytes.NewBuffer(requestJSON))
	if err != nil {
		return nil, nil, fmt.Errorf("error creating request: %w", err)
	}

	// Add headers
	httpRequest.Header.Add(SignatureHeaderTimestampKey, timeStamp)
	httpRequest.Header.Add(SignatureHeaderKey, signature)
	httpRequest.Header.Add(SignatureHeaderEndpoint, endpoint)
	httpRequest.Header.Add("Content-Type", "application/json")

	// Perform the request
	client := &http.Client{}
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("error making request: %w", err)
	}
	defer httpResponse.Body.Close()

	// Read the response body
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Return the status code and response body
	statusCode := httpResponse.StatusCode
	body := string(responseBody)
	return &statusCode, &body, nil
}

func main() {
	// Example usage
	endpoint := "http://localhost:9091/webhook/create"
	requestPayload := map[string]interface{}{
		"id":         "123",
		"merchantId": "123",
		"eventType":  "test",
		"payload": map[string]interface{}{
			"test": "test",
		},
	}

	secretKey := "secret_key"
	statusCode, responseBody, err := makeRequest(endpoint, requestPayload, secretKey)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Status Code: %d\nResponse Body: %s\n", *statusCode, *responseBody)
	}
}
```

Example checking signature process in Js:

```js
const crypto = require("crypto");

function validateWebhook(headers, body, secretKey) {
  const signature = headers["X-App-Access-Sig"];
  const timestamp = headers["X-App-Access-Timestamp"];
  const endpoint = headers["X-App-Access-Endpoint"];

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
