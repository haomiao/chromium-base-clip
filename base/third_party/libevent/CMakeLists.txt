# libevent
#################################################################################
set(my_target "libevent")
set(TARGET ${my_target})
set(TOOLSET "target")
# lib shared static
set(my_lib STATIC)
message("${my_target} library=${my_lib}")

# srcs
list(APPEND my_srcs
    buffer.c
    evbuffer.c
    evdns.c
    evdns.h
    event-config.h
    event-internal.h
    event.c
    event.h
    event_tagging.c
    evhttp.h
    evrpc-internal.h
    evrpc.c
    evrpc.h
    evsignal.h
    evutil.c
    evutil.h
    http-internal.h
    http.c
    log.c
    log.h
    min_heap.h
    poll.c
    select.c
    signal.c
    strlcpy-internal.h
    strlcpy.c
)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND my_srcs
        linux/config.h
        linux/event-config.h
        epoll.c
    )
    include_directories(linux)
endif()
source_group("libevent" FILES ${my_srcs})

# add_library 
add_library(${my_target} ${my_lib} ${my_srcs})
target_include_directories(${my_target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/..)
target_compile_definitions(${my_target} PRIVATE HAVE_CONFIG_H HAVE_STRUCT_IN6_ADDR NOMINMAX)
#target_link_libraries(${my_target} yx quic)

unset(my_srcs)
unset(my_target)
unset(my_lib)
unset(TOOLSET)
unset(TARGET)