#!/bin/bash

# Script to securely store Gemini API key in AWS Systems Manager Parameter Store
# Usage: ./store_gemini_api_key.sh YOUR_API_KEY_HERE

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 YOUR_GEMINI_API_KEY"
    echo ""
    echo "This script will store your Gemini API key securely in AWS Systems Manager Parameter Store."
    echo "The key will be encrypted and accessible only to your Lambda functions."
    echo ""
    echo "Example: $0 AIzaSyC..."
    exit 1
fi

API_KEY="$1"
PARAMETER_NAME="/science-quote-dropbox/gemini-api-key"

echo "Storing Gemini API key in AWS Systems Manager Parameter Store..."
echo "Parameter name: $PARAMETER_NAME"

# Store the API key as a SecureString (encrypted)
aws ssm put-parameter \
    --name "$PARAMETER_NAME" \
    --value "$API_KEY" \
    --type "SecureString" \
    --description "Gemini API key for Science Quote Dropbox Lambda functions" \
    --overwrite

echo "✅ API key stored successfully!"
echo ""
echo "The key is now available to your Lambda functions via environment variable:"
echo "GEMINI_API_KEY: '{{resolve:ssm:/science-quote-dropbox/gemini-api-key}}'"
echo ""
echo "To verify the parameter was stored correctly:"
echo "aws ssm describe-parameters --parameter-filters \"Key=Name,Values=$PARAMETER_NAME\"" 