// Copyright (c) 2019 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VERUS_MERGEMINING_H
#define VERUS_MERGEMINING_H

#include "amount.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "core_io.h"
#ifdef ENABLE_MINING
#include "crypto/equihash.h"
#endif
#include "init.h"
#include "main.h"
#include "metrics.h"
#include "miner.h"
#include "net.h"
#include "pow.h"
#include "rpc/server.h"
#include "txmempool.h"
#include "util.h"
#include "validationinterface.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

using namespace std;

// Each merge mined block gets an entry that includes information required to connect to a live daemon
// for that block. when a block is added to or removed from this vector, it is also added to or removed from
// the current block solution, such that all blocks from chains being merge mined are kept as up to date as
// possible. When a block is found for any of the embedded headers, submitmergedblock may be called, and
// it will submit all valid blocks to each of their respective daemons and return a composite of the results
// back. optionally, the client may choose to call each daemon's submitblock method individually for more
// control.
class CMergeMinedBlockData
{
public:
    uint256         chainID;
    std::string     symbol;
    std::string     rpcHost;
    int             rpcPort;
    std::string     rpcUserPass;
    CTransaction    chainTx;
    CBlock          block;
    std::vector<std::string> nodes;
};

#endif // VERUS_MERGEMINING_H