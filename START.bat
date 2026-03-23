@echo off
title FraudShield Backend
cd "C:\Users\Lenovo\Desktop\phishing-detector\backend"
echo Starting FraudShield Backend...
py -3.11 -m uvicorn main:app --port 8000
pause