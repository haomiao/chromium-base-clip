set(EXECUTABLE_NAME chrome_base_unittest)

set(SRC_GRP_ALLOCATOR_UNITTEST
  ../allocator/partition_allocator/address_space_randomization_unittest.cc
  ../allocator/partition_allocator/page_allocator_unittest.cc
  ../allocator/partition_allocator/spin_lock_unittest.cc
  ../allocator/tcmalloc_unittest.cc
)

set(SRC_GRP_CONTAINERS_UNITTEST
  ../containers/adapters_unittest.cc
  ../containers/linked_list_unittest.cc
  ../containers/mru_cache_unittest.cc
  ../containers/small_map_unittest.cc
  ../containers/stack_container_unittest.cc
)

set(SRC_GRP_DEBUG_UNITTEST
  ../debug/activity_analyzer_unittest.cc
  ../debug/activity_tracker_unittest.cc
  ../debug/alias_unittest.cc
  ../debug/crash_logging_unittest.cc
  ../debug/debugger_unittest.cc
  ../debug/leak_tracker_unittest.cc
  ../debug/stack_trace_unittest.cc
  ../debug/task_annotator_unittest.cc
)

set(SRC_GRP_STRINGS_UNITTEST
  ../strings/char_traits_unittest.cc
  ../strings/nullable_string16_unittest.cc
  ../strings/pattern_unittest.cc
  ../strings/safe_sprintf_unittest.cc
  ../strings/string16_unittest.cc
  ../strings/stringize_macros_unittest.cc
  ../strings/stringprintf_unittest.cc
  ../strings/string_number_conversions_unittest.cc
  ../strings/string_piece_unittest.cc
  ../strings/string_split_unittest.cc
  ../strings/string_tokenizer_unittest.cc
  ../strings/string_util_unittest.cc
  ../strings/utf_string_conversions_unittest.cc
)

set(SRC_GRP_GTEST
  ../third_party/googletest/src/googletest/src/gtest-all.cc
)

source_group("allocator"
  FILES
    ${SRC_GRP_ALLOCATOR_UNITTEST}
)

source_group("containers"
  FILES
    ${SRC_GRP_CONTAINERS_UNITTEST}
)

source_group("debug"
  FILES
    ${SRC_GRP_DEBUG_UNITTEST}
)

source_group("strings"
  FILES
    ${SRC_GRP_STRINGS_UNITTEST}
)

source_group("gtest"
  FILES
    ${SRC_GRP_GTEST}
)

set(EXECUTABLE_SRCS
  main.cpp
  ${SRC_GRP_ALLOCATOR_UNITTEST}
  ${SRC_GRP_CONTAINERS_UNITTEST}
  ${SRC_GRP_STRINGS_UNITTEST}
  ${SRC_GRP_GTEST}
  ${SRC_GRP_DEBUG_UNITTEST}
)

include_directories(
  ../
  ../breakpad
  ../third_party/googletest/src/googletest
  ../third_party/googletest/src/googletest/include
  ../third_party/googletest/src/googlemock/include
  )

add_executable(${EXECUTABLE_NAME}
  ${EXECUTABLE_SRCS}
)

target_link_libraries(${EXECUTABLE_NAME}
  chrome_base
)

if(WIN32)
target_link_libraries(${EXECUTABLE_NAME}
  shlwapi
)
endif()

#[[
set_target_properties(${EXECUTABLE_NAME}
  PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
)
]]

add_definitions(-DUNIT_TEST)
SET_COMMON_TARGET_PROPERTIES(chrome_base_unittest)