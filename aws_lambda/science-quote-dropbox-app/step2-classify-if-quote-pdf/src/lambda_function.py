import json
import base64
import boto3
import hashlib
import os
import httpx
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization  # Added for PEM→DER conversion
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#import snowflake.connector
#from snowflake.connector import DictCursor

# SQLAlchemy imports
from sqlalchemy import create_engine, Column, String, Boolean, Float, DateTime, Integer, Text, Date, func, insert, update
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import select, case, and_

# Configure standard logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

## LAMBDA FUNCTION STEP 2 BRAINSTORMING:
## 1. Get the original PDF from the S3 bucket.
## 2. Make a content based hash of the PDF (i.e. SHA256).
## 3. Use Gemini visual model API to get a yes/no answer if this looks like a quote for scientific purchasing.
## 4. If no, delete the original PDF and log the hash to a database to enable ignoring it in the future.
## 5. If yes, encrypt the PDF using the hash as the filename, and use the hash plus a fixed string as the encryption key.
## 6. Upload the encrypted PDF to the S3 bucket
## 7. Return the URL of the encrypted PDF
## 8. Delete the original PDF from the S3 bucket

# Structured output schema for Gemini Vision API
class QuoteAnalysisResult(BaseModel):
    is_scientific_quote: bool = Field(
        description="Whether this document appears to be a quote for scientific purchasing"
    )
    confidence: float = Field(
        description="Confidence level in the classification (0.0 to 1.0)",
        ge=0.0,
        le=1.0
    )
    reasoning: str = Field(
        description="Brief explanation of why this is or is not classified as a scientific quote"
    )
    document_type: str = Field(
        description="Type of document identified (e.g., 'quote', 'invoice', 'receipt', 'other')"
    )

# SQLAlchemy Base
Base = declarative_base()

# ORM Models
class PdfAnalysisResult(Base):
    __tablename__ = 'PDF_ANALYSIS_RESULTS'
    
    pdf_hash = Column(String(64), primary_key=True)
    original_key = Column(String(500), nullable=False)
    is_scientific_quote = Column(Boolean, nullable=False)
    confidence = Column(Float, nullable=False)
    reasoning = Column(Text, nullable=False)
    document_type = Column(String(100), nullable=False)
    processing_duration_ms = Column(Integer, nullable=False)
    file_size_mb = Column(Float, nullable=False)
    processed_at = Column(DateTime, nullable=False)

class DailyProcessingStats(Base):
    __tablename__ = 'DAILY_PROCESSING_STATS'
    
    processing_date = Column(Date, primary_key=True)
    total_documents = Column(Integer, nullable=False)
    scientific_quotes = Column(Integer, nullable=False)
    non_scientific = Column(Integer, nullable=False)
    avg_confidence = Column(Float, nullable=False)
    processing_success_rate = Column(Float, nullable=False)
    created_at = Column(DateTime, nullable=False, default=func.current_timestamp())

class SnowflakeConnector:
    """Handles Snowflake database connections and operations"""
    
    def __init__(self):
        self.engine = None
        
    def get_credentials(self):
        """Retrieve Snowflake credentials from AWS Secrets Manager"""
        try:
            secret_name = os.environ.get('SNOWFLAKE_SECRET_NAME', 'snowflake-credentials')
            region_name = os.environ.get('AWS_REGION', 'us-east-2')
            
            session = boto3.session.Session()
            client = session.client(
                service_name='secretsmanager',
                region_name=region_name
            )
            
            get_secret_value_response = client.get_secret_value(SecretId=secret_name)
            secret = get_secret_value_response['SecretString']
            

            
            try:
                credentials = json.loads(secret)
            except json.JSONDecodeError as json_error:
                logger.error(f"JSON parsing error: {json_error}")
                logger.error(f"Error position: {json_error.pos}")
                logger.error(f"Context around error: '{secret[max(0, json_error.pos-50):json_error.pos+50]}'")
                raise Exception(f"Invalid JSON in Secrets Manager: {json_error}")
            
            logger.info("Successfully retrieved Snowflake credentials from Secrets Manager")
            return credentials
            
        except Exception as e:
            logger.error(f"Failed to retrieve Snowflake credentials: {str(e)}")
            raise Exception(f"Failed to retrieve Snowflake credentials: {str(e)}")
    
    def connect(self):
        """Establish connection to Snowflake using SQLAlchemy"""
        if self.engine:
            return self.engine
            
        try:
            creds = self.get_credentials()
            
            # Parse private key from string format
            private_key_raw = creds['private_key']
            
            # Handle JSON-escaped newlines
            if '\\n' in private_key_raw:
                logger.info("Private key is JSON-escaped")
                private_key = private_key_raw.replace('\\n', '\n')
            else:
                logger.info("Assuming private key is already properly formatted")
                private_key = private_key_raw
            
            # Trim whitespace from the private key. If it ends with \\n in the AWS Secrets Manager, this will remove it.
            private_key = private_key.strip()
            
            
            # Validate PEM format for key-pair authentication
            if not private_key.startswith('-----BEGIN PRIVATE KEY-----'):
                logger.error("Private key does not start with correct PEM header")
                raise Exception("Invalid private key format for key-pair authentication")
            
            if not private_key.endswith('-----END PRIVATE KEY-----'):
                logger.error("Private key does not end with correct PEM footer")
                raise Exception("Invalid private key format for key-pair authentication")
            
            logger.info("Private key PEM format validation passed")
            
            # Convert PEM to DER format for Snowflake Python connector
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                
                # Load the private key from PEM format (no passphrase)
                private_key_obj = load_pem_private_key(
                    private_key.encode('utf-8'),
                    password=None
                )
                
                # Convert to DER format and then to base64
                # Use PKCS8 format which is the standard for RSA private keys
                der_private_key = private_key_obj.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                # Convert to base64 string for Snowflake
                private_key_for_snowflake = base64.b64encode(der_private_key).decode('utf-8')
                logger.info("Successfully converted PEM private key to base64-encoded DER format")

                
            except Exception as e:
                logger.error(f"Failed to convert private key from PEM to DER: {str(e)}")
                # Try alternative approach - use PEM directly if DER conversion fails
                logger.info("Attempting to use PEM format directly as fallback...")
                private_key_for_snowflake = private_key
                logger.warning("Using PEM format directly - this may not work with all Snowflake connector versions")
            
            logger.info("Using private key without passphrase")
            
            # Handle account identifier
            organization = creds.get('organization')
            account_name = creds['account']
            account_locator = creds.get('account-locator')
            
            # For key-pair authentication, use the regionless account format
            if organization and account_name:
                account = f"{organization.lower()}-{account_name}"
                logger.info(f"Using regionless account format: {account}")
            elif account_locator:
                account = account_locator
                logger.info(f"Using account locator format: {account_locator}")
            else:
                account = account_name
                logger.warning(f"Account locator not found, using account name as fallback: {account_name}")

            # Create SQLAlchemy engine for Snowflake with private key authentication
            connection_string = f"snowflake://{creds['user']}@{account}/{creds['database']}/{creds['schema']}?warehouse={creds['warehouse']}"
            
            self.engine = create_engine(
                connection_string,
                connect_args={
                    'private_key': private_key_for_snowflake,  # Use base64-encoded DER format
                    'login_timeout': 60,
                    'network_timeout': 30
                },
                pool_pre_ping=True,
                pool_recycle=3600
            )
            
            logger.info("Successfully created SQLAlchemy engine for Snowflake")
            return self.engine
            
        except Exception as e:
            logger.error(f"Failed to connect to Snowflake: {str(e)}")
            raise Exception(f"Failed to connect to Snowflake: {str(e)}")
    
    def check_existing_record(self, pdf_hash: str) -> Dict[str, Any]:
        """Check if PDF hash already exists in database using SQLAlchemy ORM"""
        try:
            self.connect()  # Ensure engine is created
            connection = self.engine.connect()
            
            try:
                # Use SQLAlchemy ORM query with proper connection handling
                stmt = select(PdfAnalysisResult).where(PdfAnalysisResult.pdf_hash == pdf_hash)
                result = connection.execute(stmt).scalar_one_or_none()
                
                if result:
                    logger.info(f"✅ PDF with hash {pdf_hash} already processed")
                    return {
                        'exists': True,
                        'data': {
                            'pdf_hash': result.pdf_hash,
                            'original_key': result.original_key,
                            'is_scientific_quote': result.is_scientific_quote,
                            'confidence': result.confidence,
                            'reasoning': result.reasoning,
                            'document_type': result.document_type,
                            'processed_at': result.processed_at.isoformat() if result.processed_at else None
                        }
                    }
                else:
                    logger.info(f"📝 PDF with hash {pdf_hash} not found in database, will process")
                    return {'exists': False, 'data': None}
                    
            finally:
                connection.close()
                
        except Exception as e:
            logger.error(f"❌ Error checking existing record: {str(e)}")
            # Continue processing even if check fails
            return {'exists': False, 'data': None}
    
    def insert_analysis_result(self, pdf_hash: str, object_key: str, 
                              analysis_result: QuoteAnalysisResult, 
                              processing_time_ms: int = 0, 
                              file_size_mb: float = 0.0) -> bool:
        """Insert analysis result into Snowflake using SQLAlchemy ORM"""
        try:
            self.connect()  # Ensure engine is created
            connection = self.engine.connect()
            
            try:
                # Use direct SQL insert with SQLAlchemy Core
                insert_stmt = insert(PdfAnalysisResult).values(
                    pdf_hash=pdf_hash,
                    original_key=object_key,
                    is_scientific_quote=analysis_result.is_scientific_quote,
                    confidence=analysis_result.confidence,
                    reasoning=analysis_result.reasoning,
                    document_type=analysis_result.document_type,
                    processing_duration_ms=processing_time_ms,
                    file_size_mb=file_size_mb,
                    processed_at=datetime.utcnow()
                )
                
                # Execute the insert
                connection.execute(insert_stmt)
                connection.commit()
                
                logger.info(f"✅ Successfully stored analysis result in Snowflake using ORM")
                return True
                
            except Exception as e:
                logger.error(f"❌ Error storing result in Snowflake: {str(e)}")
                connection.rollback()
                return False
            finally:
                connection.close()
                
        except Exception as e:
            logger.error(f"❌ Error connecting to Snowflake: {str(e)}")
            return False
    
    def update_daily_stats(self):
        """Update daily processing statistics using SQLAlchemy ORM"""
        try:
            self.connect()  # Ensure engine is created
            connection = self.engine.connect()
            
            try:
                # Get current date
                current_date = datetime.now().date()
                
                # Calculate daily statistics using SQLAlchemy ORM
                today_results = connection.execute(
                    select(
                        func.count().label('total_documents'),
                        func.sum(case((PdfAnalysisResult.is_scientific_quote == True, 1), else_=0)).label('scientific_quotes'),
                        func.sum(case((PdfAnalysisResult.is_scientific_quote == False, 1), else_=0)).label('non_scientific'),
                        func.avg(PdfAnalysisResult.confidence).label('avg_confidence')
                    ).where(
                        func.date(PdfAnalysisResult.processed_at) == current_date
                    )
                ).first()
                
                if today_results and today_results.total_documents > 0:
                    # Calculate processing success rate (assuming all records are successful if they exist)
                    processing_success_rate = 1.0
                    
                    # Check if stats for today already exist - handle potential table/column issues
                    try:
                        existing_stats = connection.execute(
                            select(DailyProcessingStats).where(DailyProcessingStats.processing_date == current_date)
                        ).scalar_one_or_none()
                        
                        if existing_stats:
                            # Update existing record using SQLAlchemy Core - don't update created_at
                            update_stmt = update(DailyProcessingStats).where(
                                DailyProcessingStats.processing_date == current_date
                            ).values(
                                total_documents=today_results.total_documents,
                                scientific_quotes=today_results.scientific_quotes or 0,
                                non_scientific=today_results.non_scientific or 0,
                                avg_confidence=today_results.avg_confidence or 0.0,
                                processing_success_rate=processing_success_rate
                            )
                            connection.execute(update_stmt)
                        else:
                            # Create new record using SQLAlchemy Core - let created_at use default
                            insert_stmt = insert(DailyProcessingStats).values(
                                processing_date=current_date,
                                total_documents=today_results.total_documents,
                                scientific_quotes=today_results.scientific_quotes or 0,
                                non_scientific=today_results.non_scientific or 0,
                                avg_confidence=today_results.avg_confidence or 0.0,
                                processing_success_rate=processing_success_rate
                            )
                            connection.execute(insert_stmt)
                        
                        connection.commit()
                        logger.info("✅ Updated daily processing statistics using ORM")
                        
                    except Exception as table_error:
                        # If the DAILY_PROCESSING_STATS table doesn't exist or has issues, just log it
                        logger.warning(f"⚠️ Could not update daily stats table: {str(table_error)}")
                        logger.info("📝 Daily stats table may not exist or have different schema - this is non-critical")
                        # Don't re-raise the exception since this is non-critical functionality
                        
                else:
                    logger.info("📝 No results found for today, skipping daily stats update")
                
            except Exception as e:
                logger.warning(f"⚠️ Failed to update daily stats (non-critical): {str(e)}")
                connection.rollback()
            finally:
                connection.close()
                
        except Exception as e:
            logger.warning(f"⚠️ Failed to connect for daily stats update: {str(e)}")
    
    def close(self):
        """Close SQLAlchemy engine and connections"""
        if self.engine:
            self.engine.dispose()
            logger.info("SQLAlchemy engine disposed")

class GeminiVisionAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key ## From https://aistudio.google.com/app/apikey
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        self.model = "gemini-2.5-flash-lite"  # 
        
    def analyze_pdf_for_quote(self, pdf_base64: str) -> QuoteAnalysisResult:
        """Analyze PDF using Gemini Vision API with structured output"""
        
        # Create the request payload with structured output
        payload = {
            "contents": [{
                "parts": [
                    {
                        "text": """Analyze this PDF document and determine if it appears to be a quote for scientific purchasing.

Look for indicators such as:
- Quote numbers, pricing information
- Scientific equipment, laboratory supplies, research materials
- Academic or research institution names
- Technical specifications
- Terms and conditions typical of scientific procurement

Respond with structured output indicating whether this is a scientific quote."""
                    },
                    {
                        "inline_data": {
                            "mime_type": "application/pdf",
                            "data": pdf_base64
                        }
                    }
                ]
            }],
            "generationConfig": {
                "temperature": 0.1,  # Low temperature for consistent classification
                "maxOutputTokens": 1024,
                "response_mime_type": "application/json",  # Fixed: moved into generationConfig
                "response_schema": {  # Fixed: moved into generationConfig
                    "type": "object",
                    "properties": {
                        "is_scientific_quote": {
                            "type": "boolean",
                            "description": "Whether this document appears to be a quote for scientific purchasing"
                        },
                        "confidence": {
                            "type": "number",
                            "description": "Confidence level in the classification (0.0 to 1.0)",
                            "minimum": 0.0,
                            "maximum": 1.0
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Brief explanation of why this is or is not classified as a scientific quote"
                        },
                        "document_type": {
                            "type": "string",
                            "description": "Type of document identified (e.g., 'quote', 'invoice', 'receipt', 'other')"
                        }
                    },
                    "required": ["is_scientific_quote", "confidence", "reasoning", "document_type"]
                }
            }
        }
        
        url = f"{self.base_url}/{self.model}:generateContent"
        
        try:
            with httpx.Client(timeout=30.0) as client:
                headers = {
                    "Content-Type": "application/json",
                    "x-goog-api-key": self.api_key
                }
                response = client.post(url, json=payload, headers=headers)
                
                # Add debugging information
                logger.info(f"API Response Status: {response.status_code}")
                logger.info(f"API Response Headers: {dict(response.headers)}")
                
                if response.status_code != 200:
                    logger.error(f"API Error Response: {response.text}")
                    response.raise_for_status()
                
                result = response.json()
                logger.info(f"API Response JSON: {json.dumps(result, indent=2)}")
                
                # Additional debugging for response structure
                if "candidates" in result:
                    logger.info(f"Number of candidates: {len(result['candidates'])}")
                    for i, candidate in enumerate(result["candidates"]):
                        logger.info(f"Candidate {i}: {json.dumps(candidate, indent=2)}")
                else:
                    logger.warning("No 'candidates' key found in response")
                    logger.info(f"Available keys: {list(result.keys())}")
                
                # Extract the structured response
                if "candidates" in result and len(result["candidates"]) > 0:
                    candidate = result["candidates"][0]
                    if "content" in candidate and "parts" in candidate["content"]:
                        for part in candidate["content"]["parts"]:
                            if "text" in part:
                                text_content = part["text"].strip()
                                if not text_content:
                                    logger.warning("Received empty text response from Gemini API")
                                    continue
                                
                                try:
                                    # Parse the JSON response
                                    analysis_data = json.loads(text_content)
                                    return QuoteAnalysisResult(**analysis_data)
                                except json.JSONDecodeError as json_error:
                                    logger.error(f"Failed to parse JSON response: {json_error}")
                                    logger.error(f"Raw text content: {repr(text_content)}")
                                    # Try to extract JSON from the response if it's wrapped in markdown
                                    if text_content.startswith("```json"):
                                        json_start = text_content.find("```json") + 7
                                        json_end = text_content.rfind("```")
                                        if json_end > json_start:
                                            json_content = text_content[json_start:json_end].strip()
                                            try:
                                                analysis_data = json.loads(json_content)
                                                return QuoteAnalysisResult(**analysis_data)
                                            except json.JSONDecodeError:
                                                logger.error("Failed to parse JSON from markdown wrapper")
                                    continue
                
                # If we get here, we couldn't parse any valid response
                logger.error("No valid JSON response found in Gemini API response")
                logger.error(f"Full API response: {json.dumps(result, indent=2)}")
                raise Exception("No valid JSON response from Gemini API")
                
        except Exception as e:
            logger.error(f"Error calling Gemini Vision API: {str(e)}")
            logger.error(f"Request URL: {url}")
            logger.error(f"Request payload: {json.dumps(payload, indent=2)}")
            # Return a default result indicating it's not a quote if API fails
            return QuoteAnalysisResult(
                is_scientific_quote=False,
                confidence=0.0,
                reasoning=f"API call failed: {str(e)}",
                document_type="unknown"
            )

def encrypt_pdf(pdf_content: bytes, pdf_hash: str, gemini_api_key: str) -> bytes:
    """Encrypt PDF content using Fernet symmetric encryption with key derived from hash and API key"""
    # Create password from combined hash and API key
    password = f"{pdf_hash}_{gemini_api_key}".encode('utf-8')
    
    # Create deterministic salt from PDF hash (first 16 bytes)
    salt = hashlib.sha256(pdf_hash.encode('utf-8')).digest()[:16]
    
    # Use PBKDF2HMAC to derive a proper key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    
    # Derive the key and encode for Fernet
    key = base64.urlsafe_b64encode(kdf.derive(password))
    
    cipher = Fernet(key)
    encrypted_content = cipher.encrypt(pdf_content)
    return encrypted_content


def lambda_handler(event, context):
    """Lambda handler for Step 2: PDF analysis and classification using Gemini Vision API"""
    
    start_time = time.time()
    snowflake_conn = None
    
    logger.info(f"Lambda invocation started - Request ID: {context.aws_request_id}")
    logger.info(f"Event received: {json.dumps(event)}")
    
    try:
        # Initialize connections
        s3_client = boto3.client('s3')
        snowflake_conn = SnowflakeConnector()
        
        # Get environment variables
        source_bucket = os.environ.get('SOURCE_BUCKET', 'science-quote-dropbox-raw-uploads')
        processed_bucket = os.environ.get('PROCESSED_BUCKET', 'science-quote-dropbox-processed-files')
        
        logger.info(f"Environment variables:")
        logger.info(f"  SOURCE_BUCKET: {source_bucket}")
        logger.info(f"  PROCESSED_BUCKET: {processed_bucket}")
        
        # Get Gemini API key from SSM Parameter Store
        ssm_client = boto3.client('ssm')
        try:
            response = ssm_client.get_parameter(
                Name='/science-quote-dropbox/gemini-api-key',
                WithDecryption=True
            )
            gemini_api_key = response['Parameter']['Value']
            logger.info("Successfully retrieved Gemini API key from SSM Parameter Store")
        except Exception as e:
            logger.error(f"Failed to retrieve Gemini API key from SSM Parameter Store: {str(e)}")
            raise Exception(f"Failed to retrieve Gemini API key from SSM Parameter Store: {str(e)}")
        
        if not gemini_api_key:
            logger.error("Gemini API key not found in SSM Parameter Store")
            raise Exception("Gemini API key not found in SSM Parameter Store")
        
        # Step 1: Get the original PDF from S3
        # Extract bucket and key from the event
        if 'Records' in event and len(event['Records']) > 0:
            s3_record = event['Records'][0]['s3']
            bucket_name = s3_record['bucket']['name']
            object_key = s3_record['object']['key']
        else:
            # For testing or direct invocation
            bucket_name = source_bucket
            object_key = event.get('object_key', 'test.pdf')
        
        logger.info(f"Processing PDF: {bucket_name}/{object_key}")
        
        # Download the PDF from S3
        response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        pdf_content = response['Body'].read()
        file_size_mb = len(pdf_content) / (1024 * 1024)
        
        # Step 2: Create content-based hash of the PDF
        pdf_hash = hashlib.sha256(pdf_content).hexdigest()
        logger.info(f"PDF hash: {pdf_hash}")
        
        # Check if we've already processed this hash (to avoid reprocessing)
        logger.info(f"Checking if PDF hash {pdf_hash} has been processed before...")
        
        existing_record = snowflake_conn.check_existing_record(pdf_hash)
        
        if existing_record['exists']:
            existing_data = existing_record['data']
            
            ## Delete original PDF from S3
            s3_client.delete_object(Bucket=source_bucket, Key=object_key)
            logger.info(f"✅ Deleted original PDF from S3: {object_key}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'PDF already processed',
                    'pdf_hash': pdf_hash,
                    'is_scientific_quote': existing_data.get('is_scientific_quote', False),
                    'original_key': existing_data.get('original_key', 'unknown'),
                    'processed_at': existing_data.get('processed_at', 'unknown')
                })
            }
        
        # Step 3: Use Gemini Vision API to analyze the PDF
        gemini_api = GeminiVisionAPI(gemini_api_key)
        
        # Convert PDF to base64 for API call
        pdf_base64 = base64.b64encode(pdf_content).decode('utf-8')
        
        # Validate PDF size (Gemini has limits on input size)
        logger.info(f"PDF size: {file_size_mb:.2f} MB")
        
        if file_size_mb > 20:  # Gemini typically has a 20MB limit
            logger.warning(f"PDF too large ({file_size_mb:.2f} MB), skipping analysis")
            analysis_result = QuoteAnalysisResult(
                is_scientific_quote=False,
                confidence=0.0,
                reasoning=f"PDF too large for analysis ({file_size_mb:.2f} MB)",
                document_type="unknown"
            )
        else:
            logger.info("Calling Gemini Vision API for analysis...")
            analysis_result = gemini_api.analyze_pdf_for_quote(pdf_base64)
        
        logger.info(f"Analysis result: {analysis_result.model_dump_json()}")

        ## Delete the original PDF from S3
        s3_client.delete_object(Bucket=source_bucket, Key=object_key)
        logger.info(f"✅ Deleted original PDF from S3: {object_key}")

        if analysis_result.is_scientific_quote:
            ## Encrypt the still in-memory PDF and upload to S3
            encrypted_pdf = encrypt_pdf(pdf_content, pdf_hash, gemini_api_key)
            encrypted_pdf_key = f"encrypted/{pdf_hash}.pdf"
            s3_client.put_object(Bucket=processed_bucket, Key=encrypted_pdf_key, Body=encrypted_pdf)
            logger.info(f"✅ Uploaded encrypted PDF to S3: {encrypted_pdf_key}")
        else:
            logger.info(f"❌ PDF is not a scientific quote, skipping encryption and S3 upload")
        
        # Store the analysis result in Snowflake
        processing_time_ms = int((time.time() - start_time) * 1000)
        logger.info(f"Storing analysis result in Snowflake...")
        
        success = snowflake_conn.insert_analysis_result(
            pdf_hash, object_key, analysis_result, processing_time_ms, file_size_mb
        )
        
        if success:
            logger.info(f"✅ Successfully stored analysis result in Snowflake")
            # Update daily statistics (optional)
            snowflake_conn.update_daily_stats()
        else:
            logger.warning(f"⚠️ Failed to store analysis result in Snowflake")
        
        # Return the analysis result
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'PDF analysis completed',
                'pdf_hash': pdf_hash,
                'original_key': object_key,
                'processing_time_ms': processing_time_ms,
                'file_size_mb': round(file_size_mb, 2),
                'analysis_result': analysis_result.model_dump()
            })
        }
        
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'processing_time_ms': int((time.time() - start_time) * 1000)
            })
        }
    finally:
        # Clean up connections
        if snowflake_conn:
            snowflake_conn.close()