# CMake generated Testfile for 
# Source directory: /root/SuperScalar
# Build directory: /root/SuperScalar/build-asan
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(unit_tests "/root/SuperScalar/build-asan/test_superscalar" "--unit")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "/root/SuperScalar/CMakeLists.txt;166;add_test;/root/SuperScalar/CMakeLists.txt;0;")
add_test(regtest_tests "/root/SuperScalar/build-asan/test_superscalar" "--regtest")
set_tests_properties(regtest_tests PROPERTIES  _BACKTRACE_TRIPLES "/root/SuperScalar/CMakeLists.txt;167;add_test;/root/SuperScalar/CMakeLists.txt;0;")
subdirs("_deps/secp256k1-zkp-build")
subdirs("_deps/cjson-build")
