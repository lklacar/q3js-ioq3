if(NOT USE_HTTP)
    return()
endif()

set(INTERNAL_CURL_DIR ${SOURCE_DIR}/thirdparty/curl-8.15.0)

if(BUILD_CLIENT AND NOT WIN32)
    find_package(CURL QUIET)

    if(NOT CURL_FOUND)
        set(CURL_DEFINITIONS USE_INTERNAL_CURL_HEADERS)
        set(CURL_INCLUDE_DIRS ${INTERNAL_CURL_DIR}/include)
    endif()

    list(APPEND CLIENT_DEFINITIONS ${CURL_DEFINITIONS})
    list(APPEND CLIENT_INCLUDE_DIRS ${CURL_INCLUDE_DIRS})
endif()

if(BUILD_SERVER)
    if(NOT CURL_FOUND)
        find_package(CURL QUIET)
    endif()

    if(CURL_FOUND)
        list(APPEND SERVER_DEFINITIONS USE_SERVER_CURL)
        list(APPEND SERVER_INCLUDE_DIRS ${CURL_INCLUDE_DIRS})

        if(TARGET CURL::libcurl)
            list(APPEND SERVER_LIBRARIES CURL::libcurl)
        else()
            list(APPEND SERVER_LIBRARIES ${CURL_LIBRARIES})
        endif()
    else()
        message(WARNING "libcurl not found: server kill post https support will be disabled")
    endif()
endif()
