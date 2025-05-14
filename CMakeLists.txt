cmake_minimum_required(VERSION 3.1...3.5)
project(kit-pov-stack C ASM)

enable_language(ASM_NASM)

set(SOURCE_FILES
  src/main.c
  src/version.c
  src/reference.c
  src/asmver.asm
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} m)
