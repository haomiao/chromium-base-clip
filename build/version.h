#ifndef _VERSION_H_
#define _VERSION_H_

#ifndef PRODUCT_VERSION_MAJOR
#define PRODUCT_VERSION_MAJOR 1
#endif //! #ifndef PRODUCT_VERSION_MAJOR

#ifndef PRODUCT_VERSION_MINOR
#define PRODUCT_VERSION_MINOR 0
#endif //! #ifndef PRODUCT_VERSION_MINOR

#ifndef PRODUCT_VERSION_PATCH
#define PRODUCT_VERSION_PATCH 0
#endif //! #ifndef PRODUCT_VERSION_PATCH

#ifndef PRODUCT_VERSION_RELEASE
#define PRODUCT_VERSION_RELEASE 0
#endif //! #ifndef PRODUCT_VERSION_RELEASE

#ifndef FILE_VERSION_MAJOR
#define FILE_VERSION_MAJOR PRODUCT_VERSION_MAJOR
#endif //! #ifndef FILE_VERSION_MAJOR

#ifndef FILE_VERSION_MINOR
#define FILE_VERSION_MINOR PRODUCT_VERSION_MINOR
#endif //! #ifndef FILE_VERSION_MINOR

#ifndef FILE_VERSION_PATCH
#define FILE_VERSION_PATCH PRODUCT_VERSION_PATCH
#endif //! #ifndef FILE_VERSION_PATCH

#ifndef FILE_VERSION_RELEASE
#define FILE_VERSION_RELEASE PRODUCT_VERSION_RELEASE
#endif //! #ifndef FILE_VERSION_RELEASE

#define _STR(R)  #R
#define STR(R) _STR(R)

#define PRODUCT_VERSION PRODUCT_VERSION_MAJOR,PRODUCT_VERSION_MINOR,PRODUCT_VERSION_PATCH,PRODUCT_VERSION_RELEASE
#define STR_PRODUCT_VERSION STR(PRODUCT_VERSION_MAJOR) "." STR(PRODUCT_VERSION_MINOR) "." STR(PRODUCT_VERSION_PATCH) "." STR(PRODUCT_VERSION_RELEASE)

#define FILE_VERSION FILE_VERSION_MAJOR,FILE_VERSION_MINOR,FILE_VERSION_PATCH,FILE_VERSION_RELEASE
#define STR_FILE_VERSION STR(FILE_VERSION_MAJOR) "." STR(FILE_VERSION_MINOR) "." STR(FILE_VERSION_PATCH) "." STR(FILE_VERSION_RELEASE)

#ifndef COMPANY_NAME
#define COMPANY_NAME  "HUYA"
#endif

#ifndef LEGAL_COPY_RIGHT
#define LEGAL_COPY_RIGHT  "Copyright (C) 2019 Huya"
#endif

#ifndef PRODUCT_NAME
#define PRODUCT_NAME  "CPPEngine"
#endif

#ifndef COMMIT_ID
#define COMMIT_ID ""
#endif
#define PRODUCT_INFO LEGAL_COPY_RIGHT "\nVersion:" STR_PRODUCT_VERSION "\nCommit id:" COMMIT_ID

#ifdef WIN32
#define STR_WATCH_DIR "D:\\"
#define STR_VERSION_DIR_PRIFIX "win32.release.cppengine_"
#else
#define STR_WATCH_DIR "/data"
#define STR_VERSION_DIR_PRIFIX "linux.release.cppengine_"
#endif

#endif //! #ifndef _VERSION_H_
