add_pic(
    ${PROJECT_NAME}
    entry.cpp
    PUBLIC_HEADER
        freshrdi.hpp
)

add_dependencies(freshrdi-pe messagebox-header)
target_link_libraries(${PROJECT_NAME}-pe PRIVATE messagebox-header)

if (AL_TESTS)
    target_link_libraries(al-test PRIVATE ${PROJECT_NAME} messagebox-header phnt_headers)
    target_sources(al-test PRIVATE freshrdi_test.cpp)
endif()
