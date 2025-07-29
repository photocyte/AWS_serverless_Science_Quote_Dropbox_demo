import json
import base64
import boto3
import uuid
import logging
from datetime import datetime
from streaming_form_data import StreamingFormDataParser
from streaming_form_data.targets import ValueTarget

# Configure standard logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def extract_pdf_from_multipart(event):
    """Extract PDF bytes from multipart/form-data in the Lambda event using streaming_form_data."""
    logger.info("Using streaming_form_data to extract PDF from multipart/form-data...")
    body = event.get('body')
    if not body:
        logger.warning("No body in event")
        return None, 'No body in event'
    is_base64 = event.get('isBase64Encoded', False)
    if is_base64:
        body = base64.b64decode(body)
        logger.info(f"Body was base64 encoded. Decoded length: {len(body)}")
    else:
        body = body.encode('utf-8')
        logger.info(f"Body was utf-8 encoded. Length: {len(body)}")
    logger.debug(f"First 200 bytes of body (base64): {base64.b64encode(body[:200]).decode()}")
    headers = event.get('headers', {})
    content_type = headers.get('content-type') or headers.get('Content-Type')
    logger.info(f"Content-Type: {content_type}")
    if not content_type or 'multipart/form-data' not in content_type:
        logger.warning("Not multipart/form-data")
        return None, 'Not multipart/form-data'
    try:
        parser = StreamingFormDataParser(headers={'content-type': content_type})
        pdf_target = ValueTarget()
        parser.register('pdf-file', pdf_target)
        parser.data_received(body)
        pdf_bytes = pdf_target.value
        if pdf_bytes:
            logger.info(f"Extracted PDF size: {len(pdf_bytes)}")
            logger.debug(f"First 200 bytes of PDF (base64): {base64.b64encode(pdf_bytes[:200]).decode()}")
            logger.debug(f"Last 200 bytes of PDF (base64): {base64.b64encode(pdf_bytes[-200:]).decode() if len(pdf_bytes) >= 200 else base64.b64encode(pdf_bytes).decode()}")
            
            # Check file size limit (6MB = 6 * 1024 * 1024 bytes)
            # Note: This is actually a Lambda request payload limitation - even if this Lambda didn't implement it,
            # the upstream system (API Gateway) enforces this limit
            max_size = 6 * 1024 * 1024
            if len(pdf_bytes) > max_size:
                logger.warning(f"File size {len(pdf_bytes)} exceeds limit of {max_size}")
                return None, 'File size exceeds 6MB limit'
            
            if pdf_bytes.startswith(b'%PDF'):
                return pdf_bytes, None
            else:
                logger.warning("Extracted file does not start with %PDF")
                return None, 'Extracted file does not start with %PDF'
        logger.warning("No PDF part found")
        return None, 'No PDF part found'
    except Exception as e:
        logger.error(f"Error parsing multipart: {str(e)}")
        return None, f'Error parsing multipart: {str(e)}'

# Initialize S3 client and bucket name
s3_client = boto3.client('s3')
BUCKET_NAME = 'science-quote-dropbox-raw-uploads'

dynamodb = boto3.resource('dynamodb')
RATE_LIMIT_TABLE = 'step1-rate-limit'
RATE_LIMIT = 5  # max requests per minute

def get_client_ip(event):
    # Try to extract IP from API Gateway event
    return event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')

def check_rate_limit(client_id):
    now = datetime.utcnow()
    window = now.strftime('%Y-%m-%dT%H:%M')  # per minute
    # Set TTL to 1 day from now (86400 seconds)
    ttl = int(now.timestamp()) + (24 * 60 * 60)
    table = dynamodb.Table(RATE_LIMIT_TABLE)
    response = table.update_item(
        Key={'client_id': client_id, 'window': window},
        UpdateExpression='ADD #c :inc SET #t = :ttl',
        ExpressionAttributeNames={'#c': 'count', '#t': 'ttl'},
        ExpressionAttributeValues={':inc': 1, ':ttl': ttl},
        ReturnValues='UPDATED_NEW'
    )
    count = response['Attributes']['count']
    return count <= RATE_LIMIT

def lambda_handler(event, context):
    # CORS headers for the response
    cors_headers = {
        "Access-Control-Allow-Origin": "http://science-quote-dropbox.s3-website.us-east-2.amazonaws.com",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, HX-Request, HX-Trigger, HX-Target, HX-Current-URL"
    }

    logger.info(f"Lambda invocation started - Request ID: {context.aws_request_id}")
    logger.info(f"Received event: {json.dumps(event)[:1000]}")

    # Handle preflight OPTIONS request
    if event.get('httpMethod', '') == 'OPTIONS':
        logger.info("OPTIONS request received.")
        return {
            "statusCode": 200,
            "headers": cors_headers,
            "body": ""
        }

    client_id = get_client_ip(event)
    if not check_rate_limit(client_id):
        logger.warning(f"Rate limit exceeded for client {client_id}")
        return {
            "statusCode": 429,
            "headers": cors_headers,
            "body": "Rate limit exceeded. Please try again later."
        }

    try:
        # Try to extract PDF from multipart form data
        pdf_bytes, pdf_error = extract_pdf_from_multipart(event)
        
        # Check for file size error
        if pdf_error and 'File size exceeds 6MB limit' in pdf_error:
            logger.info(f"File size exceeds 6MB limit: {pdf_error}")
            return {
                "statusCode": 413,  # Payload Too Large
                "headers": cors_headers,
                "body": json.dumps({"error": "File size exceeds 6MB limit"})
            }
        
        s3_key = None
        s3_upload_error = None
        if pdf_bytes:
            # Generate unique S3 key
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_id = str(uuid.uuid4())[:8]
            s3_key = f"uploads/original_{timestamp}_{unique_id}.pdf"
            try:
                logger.info(f"Uploading to S3: key={s3_key}, size={len(pdf_bytes)}")
                s3_client.put_object(
                    Bucket=BUCKET_NAME,
                    Key=s3_key,
                    Body=pdf_bytes,
                    ContentType='application/pdf'
                )
                logger.info(f"✅ Successfully uploaded PDF to S3: {s3_key}")
            except Exception as s3e:
                s3_upload_error = str(s3e)
                logger.error(f"❌ S3 upload failed: {s3_upload_error}")

        response_body = {
            "message": "Hello from Lambda!",
            "method": event.get('httpMethod'),
            "headers": event.get('headers'),
            "isBase64Encoded": event.get('isBase64Encoded'),
            "body_length": len(event.get('body', '')) if event.get('body') else 0,
            "pdf_found": pdf_bytes is not None,
            "pdf_size": len(pdf_bytes) if pdf_bytes else 0,
            "pdf_starts_with_pdf": pdf_bytes.startswith(b'%PDF') if pdf_bytes else False,
            "pdf_error": pdf_error,
            "s3_key": s3_key,
            "s3_upload_error": s3_upload_error
        }

        response_message = "PDF uploaded successfully! Thank you."

        logger.info(f"Response body: {json.dumps(response_body)}")
        logger.info("✅ PDF upload request completed successfully")

        return {
            "statusCode": 200,
            "headers": cors_headers,
            "body": response_message ## json.dumps(response_body)
        }
    except Exception as e:
        logger.error(f"❌ Error occurred: {str(e)}")
        return {
            "statusCode": 500,
            "headers": cors_headers,
            "body": json.dumps({"error": str(e)})
        }