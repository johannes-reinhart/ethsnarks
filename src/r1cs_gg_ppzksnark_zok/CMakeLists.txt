
add_executable(test_r1cs_gg_ppzksnark_zok tests/test_r1cs_gg_zok_ppzksnark.cpp)
target_link_libraries(test_r1cs_gg_ppzksnark_zok
        ethsnarks_common
        gmpxx)
