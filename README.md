# Science Quote Dropbox
A serverless AWS application that analyzes PDF documents to identify scientific equipment quotes using AI, encrypts qualified documents, and stores analysis results in Snowflake for pricing transparency.

## 🏗️ Architecture
- **Frontend**: Static HTML & HTMX JavaScript hosted on S3
- **Backend - Step 1**: PDF upload via API Gateway → Lambda function → S3 storage
- **Backend - Step 2**: S3 trigger → Lambda function → Gemini Vision API analysis → Snowflake storage
- **Backend - Step 3+**: (For extraction of pricing data from quotes. Not yet implemented, as this is an MVP)


### Prerequisites
1. **AWS CLI** configured with appropriate permissions for an IAM user
2. **AWS SAM CLI** installed
3. **Google Gemini API Key** from [Google AI Studio](https://makersuite.google.com/app/apikey)


## 📁 Project Structure
```
aws_lambda/science-quote-dropbox-app/
├── step1-accept-pdf/            # PDF upload Lambda
├── step2-classify-if-quote-pdf/ # PDF quote classification Lambda  
├── template.yml                 # CloudFormation template
├── build_all.sh                 # Layer building script
├── deploy_all.sh                # Deployment script
└── out-of-stack-iam-policies/   # policies attatched to app IAM user by root user
```

## 🔧 Configuration

### AWS Resources
- **S3 Buckets**: Raw uploads, processed files, static website
- **Lambda Functions**: PDF upload, PDF analysis
- **API Gateway**: REST API for uploads
- **DynamoDB**: Rate limiting table
- **CloudWatch**: Logging and monitoring
- **Secrets Manager**: Snowflake credentials
- **SSM Parameter Store**: Gemini API key
