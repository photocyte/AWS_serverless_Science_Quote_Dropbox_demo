#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==============================="
echo "Step 1: Build Step 1 Lambda Layer"
echo "==============================="
(cd step1-accept-pdf && ./build.sh)

echo "==============================="
echo "Step 2: Build Step 2 Lambda Layer"
echo "==============================="
(cd step2-classify-if-quote-pdf && ./build.sh)

echo "==============================="
echo "Manual Step: Publish Lambda Layers (if needed)"
echo "==============================="
cat <<EOF

To publish the Step 1 layer, run:
aws lambda publish-layer-version \
    --layer-name science-quote-dropbox-step1-layer \
    --description 'Dependencies for Step 1 PDF processing' \
    --zip-file fileb://step1-accept-pdf/lambda-layer.zip \
    --compatible-runtimes python3.13 \
    --region us-east-2

To publish the Step 2 layer, run:
aws lambda publish-layer-version \
    --layer-name science-quote-dropbox-step2-layer \
    --description 'Dependencies for Step 2 PDF encryption/anonymization' \
    --zip-file fileb://step2-classify-if-quote-pdf/lambda-layer.zip \
    --compatible-runtimes python3.13 \
    --region us-east-2
EOF

echo "==============================="
echo "All build steps complete!"
echo "===============================" 