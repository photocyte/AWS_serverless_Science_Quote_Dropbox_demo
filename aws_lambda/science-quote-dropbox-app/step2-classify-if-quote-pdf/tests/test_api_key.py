#!/usr/bin/env python3
"""
Simple test to verify the Gemini API key is working with a basic text request.
"""

import json
import httpx
import os

def test_api_key():
    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key:
        print("Error: GEMINI_API_KEY environment variable is not set")
        return False
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    
    payload = {
        "contents": [{
            "parts": [{
                "text": "Hello, this is a test message. Please respond with 'API key is working' if you can see this."
            }]
        }],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 50,
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key
    }
    
    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(url, json=payload, headers=headers)
            
            print(f"API Response Status: {response.status_code}")
            
            if response.status_code != 200:
                print(f"API Error Response: {response.text}")
                return False
            
            result = response.json()
            print(f"API Response: {json.dumps(result, indent=2)}")
            
            if "candidates" in result and len(result["candidates"]) > 0:
                candidate = result["candidates"][0]
                if "content" in candidate and "parts" in candidate["content"]:
                    for part in candidate["content"]["parts"]:
                        if "text" in part:
                            print(f"Model response: {part['text']}")
                            return True
            
            print("No valid response found")
            return False
            
    except Exception as e:
        print(f"Error testing API key: {str(e)}")
        return False

if __name__ == "__main__":
    print("Testing Gemini API key...")
    success = test_api_key()
    if success:
        print("✅ API key is working!")
    else:
        print("❌ API key test failed!") 