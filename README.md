# User Data Normalizer Variable Template for Google Tag Manager Server Container

This Google Tag Manager (GTM) **Server-Side Variable Template** normalizes and securely hashes user data (such as email
addresses and phone numbers) for privacy-compliant event forwarding to destinations like Google Enhanced Conversions,
Facebook Conversion API, etc.

## ✨ Features

- Normalizes **email addresses** (e.g., removes dots and plus-labels for Gmail).
- Normalizes **phone numbers** to international format.
- Supports both string and array input values.

When `hashUserData` is enabled:
- **SHA-256 hashes** email and phone number values.
- Prevents re-hashing of already hashed values.
- Automatically removes raw (unhashed) values.

## 🔧 Inputs

The template reads from the GTM `event_data.user_data` object.
