add_pic(
    ${PROJECT_NAME}
    entry.cpp
    PUBLIC_HEADER
        freshrdi.hpp
)

add_dependencies(${PROJECT_NAME} messagebox)
target_link_libraries(${PROJECT_NAME}-pe PRIVATE messagebox-header)
