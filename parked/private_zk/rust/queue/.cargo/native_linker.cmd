@echo off
setlocal
for /f "delims=" %%S in ('rustc.exe --print sysroot') do set "RUST_SYSROOT=%%S"
if not defined RUST_SYSROOT exit /b 1
"%RUST_SYSROOT%\lib\rustlib\x86_64-pc-windows-msvc\bin\rust-lld.exe" -flavor link %*
exit /b %ERRORLEVEL%
