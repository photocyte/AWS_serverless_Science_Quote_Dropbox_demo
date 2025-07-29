#!/bin/bash

# Test script for Gemini Vision API
# This script helps test the API call locally before deploying to Lambda

# Pos PDF path
POSITIVE_PDF_PATH="quote-positive-controls/07850090-1.pdf"
# Negative PDF path
NEGATIVE_PDF_PATH="quote-negative-controls/LabScrumGuide.pdf"

echo "Setting up test environment..."
echo "Testing with positive PDF: $POSITIVE_PDF_PATH"
echo "Testing with negative PDF: $NEGATIVE_PDF_PATH"

# Check if conda is available and activate the project-specific environment
if command -v conda &> /dev/null; then
    echo "Activating conda environment..."
    conda activate base
else
    echo "Conda not found, using system Python"
fi

# Check if GEMINI_API_KEY is set
if [ -z "$GEMINI_API_KEY" ]; then
    echo "Error: GEMINI_API_KEY environment variable is not set"
    echo "Please set it with: export GEMINI_API_KEY='your-api-key-here'"
    exit 1
fi

echo "GEMINI_API_KEY is set"

# Install dependencies if needed
echo "Installing dependencies..."
pip install httpx pydantic boto3

# Run the test with the specified PDF path
echo "Running Gemini API test with: $POSITIVE_PDF_PATH"
python test_gemini_api.py "$POSITIVE_PDF_PATH"

echo "Running Gemini API test with: $NEGATIVE_PDF_PATH"
python test_gemini_api.py "$NEGATIVE_PDF_PATH"


echo "Test completed!" 