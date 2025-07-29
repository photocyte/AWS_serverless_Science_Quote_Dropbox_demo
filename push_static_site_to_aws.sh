#!/bin/bash

set -e

STATIC_BUCKET="science-quote-dropbox"
REGION="us-east-2"

# Upload index.html and error.html to the static website bucket
aws s3 cp index.html s3://$STATIC_BUCKET/index.html --region $REGION
aws s3 cp error.html s3://$STATIC_BUCKET/error.html --region $REGION

echo "✅ index.html and error.html uploaded to $STATIC_BUCKET" 