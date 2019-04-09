// Copyright (c) 2018 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/solutiondata.h"
#include "primitives/block.h"

const int32_t numVersions = 2;
CActivationHeight CConstVerusSolutionVector::activationHeight = CActivationHeight();
CConstVerusSolutionVector CVerusSolutionVector::solutionTools;

void CConstVerusSolutionVector::SetPBaaSHeader(std::vector<unsigned char> &vch, const CPBaaSBlockHeader &pbh, int32_t idx)
{
    if (idx < GetDescriptor(vch).numPBaaSHeaders)
    {
        *(CPBaaSBlockHeader *)(&vch[0] + sizeof(CPBaaSSolutionDescriptor)) = pbh;
    }
}

bool CVerusSolutionVector::GetPBaaSHeader(CPBaaSBlockHeader &pbh, uint32_t idx) const
{
    if (idx < GetNumPBaaSHeaders())
    {
        pbh = *(GetFirstPBaaSHeader() + idx);
        return true;
    }
    return false;
}


