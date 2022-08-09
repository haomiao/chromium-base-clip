cd %~dp0
set shadowdir=build_mt_win64
if not exist %shadowdir% (
    mkdir %shadowdir%
)
cd %~dp0%shadowdir%

cmake .. -DCMAKE_CXX_STANDARD=17 -DMT=ON -DBUILD_STATIC_LIBS=ON -G "Visual Studio 16 2019" -A x64
cmake --build . --config Debug
cmake --build . --config Release

cd %~dp0
