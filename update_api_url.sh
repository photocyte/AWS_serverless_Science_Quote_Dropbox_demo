#!/bin/bash

STACK_NAME="science-quote-dropbox-app"
REGION="us-east-2"
HTML_FILE="index.html"

# Get the API URL for Step 1 from CloudFormation outputs
API_URL=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='ApiUrlStep1'].OutputValue" \
  --output text)

if [[ -z "$API_URL" || "$API_URL" == "None" ]]; then
  echo "API URL for Step 1 not found in stack outputs."
  exit 1
fi

# Update the hx-post attribute in index.html
sed -i '' "s|hx-post=\"[^\"]*\"|hx-post=\"$API_URL\"|g" "$HTML_FILE"

echo "Updated $HTML_FILE with Step 1 API URL: $API_URL" 
echo "Pushing new index.html and error.html to AWS S3..."
./push_static_site_to_aws.sh
