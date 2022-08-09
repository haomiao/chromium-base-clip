cd %~dp0
set shadowdir=build_win32
if not exist %shadowdir% (
    mkdir %shadowdir%
)
cd %~dp0%shadowdir%

cmake .. -DCMAKE_CXX_STANDARD=17 -G "Visual Studio 16 2019" -A Win32
cmake --build . --config Debug
cmake --build . --config Release

cd %~dp0
