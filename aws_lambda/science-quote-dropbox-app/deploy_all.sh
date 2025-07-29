#!/bin/bash

set -e

# Always run from the script's own directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
cd "$SCRIPT_DIR"

echo '====================================================================='
echo 'WORKAROUND: You must manually create the static website bucket and disable Block Public Access before running this script.'
echo 'Run these commands as the IAM user:'
echo '  aws s3 mb s3://science-quote-dropbox --region us-east-2'
echo '  aws s3api put-public-access-block --bucket science-quote-dropbox --public-access-block-configuration BlockPublicPolicy=false,IgnorePublicAcls=false,BlockPublicAcls=false,RestrictPublicBuckets=false --region us-east-2'
echo 'This is necessary because CloudFormation/SAM cannot create a public bucket when Block Public Access is enabled at the account level.'
echo 'And, because I couldnt figure out how to automate it as IaC'
echo '====================================================================='

# Clean previous SAM build artifacts
printf '\n🧹 Cleaning previous SAM build artifacts...\n'
rm -rf .aws-sam/build

# The following disables Block Public Access at the account level, but is commented out as a workaround is now used.
# echo '\n🔓 Disabling Block Public Access at the account level...'
# aws s3control put-public-access-block \
#   --account-id YOUR_ACCOUNT_ID \
#   --public-access-block-configuration BlockPublicPolicy=false,IgnorePublicAcls=false,BlockPublicAcls=false,RestrictPublicBuckets=false \
#   --region us-east-2
# echo '✅ Block Public Access disabled at the account level'

# Build Lambda functions with AWS SAM
printf '\n🔨 Building Lambda functions with AWS SAM...\n'
sam build --config-file samconfig.toml --template-file template.yml

# Deploy Lambda functions with AWS SAM
printf '\n🚀 Deploying Lambda functions with AWS SAM...\n'
sam deploy --config-file samconfig.toml --template-file template.yml --parameter-overrides StaticWebsiteBucketName=science-quote-dropbox

# (Optional) Re-enable Block Public Access at the account level after deployment for security
# aws s3control put-public-access-block \
#   --account-id YOUR_ACCOUNT_ID \
#   --public-access-block-configuration BlockPublicPolicy=true,IgnorePublicAcls=true,BlockPublicAcls=true,RestrictPublicBuckets=true \
#   --region us-east-2

# Enable static website hosting
aws s3 website s3://science-quote-dropbox/ \
  --index-document index.html \
  --error-document error.html \
  --region us-east-2

# Upload static website files to S3
( cd ../.. && bash update_api_url.sh )

printf '\n✅ Rebuild and deployment complete!\n\n'
