#!/usr/bin/env bash
# Generate a strong dev JWT secret.
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
