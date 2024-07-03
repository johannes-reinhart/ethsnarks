#ifndef JUBJUB_ADDER_HPP_
#define JUBJUB_ADDER_HPP_

// Copyright (c) 2018 @HarryR
// License: LGPL-3.0+

#include "jubjub/params.hpp"


namespace ethsnarks {

namespace jubjub {


class PointAdder : public GadgetT {
public:
    const Params& m_params;

    // First input point
    const LinearCombinationT m_X1;
    const LinearCombinationT m_Y1;

    // Second input point
    const LinearCombinationT m_X2;
    const LinearCombinationT m_Y2;

    // Intermediate variables
    const VariableT m_beta;
    const VariableT m_gamma;
    //const VariableT m_delta;
    //const VariableT m_epsilon;
    const VariableT m_rho;
    const VariableT m_tau;
    const VariableT m_X3;
    const VariableT m_Y3;

    PointAdder(
        ProtoboardT& in_pb,
        const Params& in_params,
        const LinearCombinationT in_X1,
        const LinearCombinationT in_Y1,
        const LinearCombinationT in_X2,
        const LinearCombinationT in_Y2,
        const std::string& annotation_prefix
    );

    const VariableT& result_x() const;

    const VariableT& result_y() const;

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_ADDER_HPP_
#endif
