# Security Policy

## Secrets

Never commit passwords, private keys, API tokens, decrypted files, `.env` files,
keystores or runtime storage. Use environment variables or a local secret manager.

## Reporting a vulnerability

Do not publish a vulnerability or real secret in a public issue. Contact the project
team privately, include reproduction steps that use test data only, and wait for the
team to confirm a fix before public disclosure.

## Current prototype limits

This educational prototype does not yet provide production authentication, durable
database persistence, malware scanning or distributed storage. Use only synthetic
test files until those controls are implemented and reviewed.
