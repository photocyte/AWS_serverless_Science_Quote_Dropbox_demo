#!/bin/bash

# This script runs 'sam deploy --guided' to help you set up your AWS SAM deployment configuration.
# It will prompt you for stack name, region, and deployment S3 bucket, and save your choices for future deployments.
#
# Usage: bash sam_guided_setup.sh

set -e

# Change to the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Note: it's best practice that sam deploy --guided, isn't allowed to create the bucket on its own"
echo "So, have to make it manually:    aws s3 mb s3://science-quote-dropbox-deploy-artifacts --region us-east-2"
echo " Also, for the static website s3 bucket 'science-quote-dropbox', have to make it manually, from the root account on AWS Console, and turn off "Block Public Access"

sam deploy --guided --template-file template.yml --s3-bucket science-quote-dropbox-deploy-artifacts
