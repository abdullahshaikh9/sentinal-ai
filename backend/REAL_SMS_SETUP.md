# Real mobile OTP delivery with Twilio

Sentinel already has a provider adapter in `app/services/otp.py`. To request real SMS, configure these values in `backend/.env` (never in Vite or frontend variables):

```dotenv
APP_ENV=development
SMS_PROVIDER=twilio
SMS_ACCOUNT_SID=AC...your-account-sid...
SMS_AUTH_TOKEN=your-account-auth-token
SMS_FROM_NUMBER=+1...your-enabled-sender...
SMS_TIMEOUT_SECONDS=10
```

Keep the existing `OTP_PEPPER` and email provider configuration. Do not use the development `console` provider in production. Restart FastAPI after changing settings.

In Twilio Console, activate Programmable Messaging, add billing/credits as required, enable destination geographic permissions for Pakistan, and use a sender/service approved for your account and the intended one-time-password use case. Twilio acceptance of the API request means the message was submitted/queued; it does not confirm handset delivery. Inspect message status and carrier errors in Twilio Console. Do not repeatedly resend during provider incidents; Sentinel's existing cooldown and OTP expiry/attempt limits continue to apply.

Twilio's current Pakistan guidance lists international long-code delivery as supported by Twilio while noting Pakistani networks do not support international long codes, dynamic sender IDs may be overwritten, and some operators may not preserve a sender ID. A2P rules apply to messages sent through Twilio; review your account's eligibility, current country guidance, carrier coverage, and pricing before relying on the service. Account setup, sender availability, approval, credits, and delivery to a particular handset are not verified by this application.

Official references:

- [Pakistan SMS guidelines](https://www.twilio.com/en-us/guidelines/pk/sms)
- [Twilio Programmable Messaging API](https://www.twilio.com/docs/messaging/api)
- [Pakistan SMS pricing](https://www.twilio.com/en-us/sms/pricing/pk)
