# SuperScalar CLN plugin skeleton.
#
# Built only when -DBUILD_CLN_PLUGIN=ON is passed at top-level configure.
# Produces a shared library (libsuperscalar_cln.so) that CLN's plugin
# loader will eventually dlopen. At this stage it is a structural skeleton
# only; real bLIP-56 wire handling lands in follow-ups (#172).

# Force-enable shared lib build for this target only — the top-level
# CMakeLists sets BUILD_SHARED_LIBS=OFF for the static libsuperscalar.a.
add_library(superscalar_cln SHARED
    superscalar_cln.c
    blip56_codec.c
)

target_include_directories(superscalar_cln
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_SOURCE_DIR}/include
)

# Link against the existing static lib only — no real CLN dep yet.
target_link_libraries(superscalar_cln
    PRIVATE superscalar project_warnings
)

if(ENABLE_SANITIZERS)
    target_link_libraries(superscalar_cln PRIVATE project_sanitizers)
endif()

set_target_properties(superscalar_cln PROPERTIES
    OUTPUT_NAME superscalar_cln
    POSITION_INDEPENDENT_CODE ON
)
