@echo off
rem cv2-vectors.cmd EXE REQUEST OUTPUT: one correction transition, stdin -> stdout file.
"%~1" --apply-correction-transition < "%~2" > "%~3"
set RC=%errorlevel%
echo VECTOR_EXIT=%RC%
exit /b %RC%
