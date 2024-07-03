/** @file
 *****************************************************************************
 Unit tests for EDDSA signature
 *****************************************************************************
 *
 *****************************************************************************/

#include "depends/libff/libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp"

#include "crypto/signatures/eddsa.h"


namespace ethsnarks{
    bool test_eddsa_serialization(size_t n){
        eddsa_private_key key;
        eddsa_public_key A;
        eddsa_generate_keypair(key, A);

        std::stringstream ss;
        for (size_t i = 0; i < n; i++){
            ss = std::stringstream();
            std::string message = std::string("Test ") + std::to_string(i);
            EddsaSignature signature_pedersen = eddsa_pedersen_sign(message, key);
            ss << signature_pedersen;
            EddsaSignature signature_pedersen2;
            ss >> signature_pedersen2;
            if( (signature_pedersen.R != signature_pedersen2.R) || (signature_pedersen.s != signature_pedersen2.s)){
                return false;
            }

            ss = std::stringstream();
            EddsaSignature signature_poseidon = eddsa_poseidon_sign(message, key);
            ss << signature_poseidon;
            EddsaSignature signature_poseidon2;
            ss >> signature_poseidon2;
            if( (signature_poseidon.R != signature_poseidon2.R) || (signature_poseidon.s != signature_poseidon2.s)){
                return false;
            }
        }
        return true;
    }

    bool test_eddsa_sign(size_t n){
        eddsa_private_key key;
        eddsa_public_key A;

        for (size_t i = 0; i < n; i++) {
            eddsa_generate_keypair(key, A);
            std::string message = std::string("Hello World ") + std::to_string(i);

            EddsaSignature signature_pedersen = eddsa_pedersen_sign(message, key);
            EddsaSignature signature_poseidon = eddsa_poseidon_sign(message, key);

            bool verify_pedersen = eddsa_pedersen_verify(message, signature_pedersen, A);
            bool verify_poseidon = eddsa_poseidon_verify(message, signature_poseidon, A);

            if (!verify_pedersen || !verify_poseidon){
                return false;
            }
        }

        return true;
    }

}


int main(int argc, char **argv) {
    ethsnarks::init_eddsa();

    if (!ethsnarks::test_eddsa_serialization(10)){
        std::cerr << "FAIL: eddsa serialization" << std::endl;
        return 1;
    }

    if (!ethsnarks::test_eddsa_sign(10)){
        std::cerr << "FAIL: eddsa sign" << std::endl;
        return 1;
    }
}
