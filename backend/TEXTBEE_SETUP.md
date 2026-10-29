# TextBee SMS setup

TextBee SMS is selected only when all of these backend settings are configured:

```dotenv
SMS_PROVIDER=textbee
TEXTBEE_ENABLED=true
TEXTBEE_API_KEY=<newly-generated-api-key>
SMS_TIMEOUT_SECONDS=10
```

Keep the key in `backend/.env`; never put it in frontend settings or source. `OTP_PEPPER` and the existing SMTP settings are still required because the account must complete both email and phone verification. `TEXTBEE_ENABLED=false` (the example default) prevents TextBee delivery even if a key is present. The service will not fall back to console logging when `SMS_PROVIDER=textbee`.

The adapter calls TextBee's account-level `POST https://api.textbee.dev/api/v1/gateway/send-sms` with the API key in `x-api-key` and JSON containing one E.164 recipient and the branded OTP message. It requires the documented `data.success`, `smsBatchId`, and `recipientCount` response fields. A timeout, non-success HTTP status, or malformed/non-acceptance response is treated as a delivery failure. No provider response body, key, or OTP is written to general logs or returned to the browser.

TextBee requires an account with a verified email and a registered, online Android device with SMS permission and an active SIM. Its HTTP 200 means the batch was accepted into the queue; it does not prove the handset or carrier delivered the message. Check TextBee Messaging History and the Android app activity to follow delivery.

If an API key has appeared in a chat or another untrusted place, create a replacement in the TextBee dashboard, update only `TEXTBEE_API_KEY` in your local `backend/.env`, verify the replacement safely, then revoke the exposed key in the dashboard. The project cannot revoke keys on your behalf. TextBee keys have broad account access, so use a key dedicated to this application.

For email, `SMTP_FROM` remains the existing sender identity. The application formats that address as `Sentinel AI <configured-address>` in the email From header. The SMTP account/provider must permit that sender identity; use a verified sender address/domain and do not substitute an unverified address.
