#!/usr/bin/env python3
"""
Test script for Gemini Vision API to debug the 400 Bad Request error.
This script can be run locally to test the API call before deploying to Lambda.
"""

import json
import base64
import os
import sys
import argparse

# Add the src directory to the Python path so we can import from lambda_function.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import the actual classes and functions from lambda_function.py
from lambda_function import GeminiVisionAPI, QuoteAnalysisResult

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Test Gemini Vision API with a PDF file')
    parser.add_argument('pdf_path', help='Path to the PDF file to test')
    parser.add_argument('--api-key', help='Gemini API key (overrides GEMINI_API_KEY env var)')
    
    args = parser.parse_args()
    
    # Get API key from argument or environment variable
    api_key = args.api_key or os.environ.get('GEMINI_API_KEY')
    if not api_key:
        print("Error: No API key provided. Use --api-key or set GEMINI_API_KEY environment variable")
        return
    
    # Test with the provided PDF path
    test_pdf_path = args.pdf_path
    
    if not os.path.exists(test_pdf_path):
        print(f"Error: PDF file not found: {test_pdf_path}")
        return
    
    # Read and encode the PDF
    with open(test_pdf_path, 'rb') as f:
        pdf_content = f.read()
    
    pdf_base64 = base64.b64encode(pdf_content).decode('utf-8')
    pdf_size_mb = len(pdf_content) / (1024 * 1024)
    print(f"PDF size: {pdf_size_mb:.2f} MB")
    
    # Test the API using the actual classes from lambda_function.py
    gemini_api = GeminiVisionAPI(api_key)
    result = gemini_api.analyze_pdf_for_quote(pdf_base64)
    
    print(f"\nAnalysis Result:")
    print(f"Is Scientific Quote: {result.is_scientific_quote}")
    print(f"Confidence: {result.confidence}")
    print(f"Reasoning: {result.reasoning}")
    print(f"Document Type: {result.document_type}")

if __name__ == "__main__":
    main() 