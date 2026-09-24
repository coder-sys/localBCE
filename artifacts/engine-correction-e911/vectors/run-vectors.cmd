@echo off
"C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-engine-20260913\semantic_kernel\lean\.lake\build\bin\blind_financial_correction.exe" --apply-correction-transition < "C:\Users\neers\AppData\Local\Temp\engine-correction-vectors-20260923-r2\request.bin" > "C:\Users\neers\AppData\Local\Temp\engine-correction-vectors-20260923-r2\result.actual.bin"
if errorlevel 1 exit /b %errorlevel%
"C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-engine-20260913\semantic_kernel\lean\.lake\build\bin\blind_financial_correction.exe" --assess-correction-reuse < "C:\Users\neers\AppData\Local\Temp\engine-correction-vectors-20260923-r2\reuse-request.bin" > "C:\Users\neers\AppData\Local\Temp\engine-correction-vectors-20260923-r2\reuse-result.actual.bin"
if errorlevel 1 exit /b %errorlevel%
exit /b 0