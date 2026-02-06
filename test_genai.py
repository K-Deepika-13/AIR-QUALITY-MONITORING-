import google.generativeai as genai
import os

FALLBACK_KEY = "AIzaSyBbT7lFb919QPHorLkSQMp0y3fmr_tv1Xs"
_genai_key = os.environ.get("GEMINI_API_KEY") or FALLBACK_KEY

print(f"Using API Key: {_genai_key[:5]}...")

try:
    genai.configure(api_key=_genai_key)
    print("[GenAI] Configured successfully.")
except Exception as e:
    print(f"[GenAI] Configuration failed: {e}")

try:
    model_name = "gemini-2.5-flash-lite"
    print(f"Testing model: {model_name}")
    model = genai.GenerativeModel(model_name)
    response = model.generate_content("Hello, are you working?")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error with {model_name}: {e}")

try:
    model_name = "gemini-1.5-flash"
    print(f"Testing model: {model_name}")
    model = genai.GenerativeModel(model_name)
    response = model.generate_content("Hello, are you working?")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error with {model_name}: {e}")
