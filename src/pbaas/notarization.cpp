/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This implements the public blockchains as a service (PBaaS) notarization protocol, VerusLink.
 * VerusLink is a new distributed consensus protocol that enables multiple public blockchains 
 * to operate as a decentralized ecosystem of chains, which can interact and easily engage in cross 
 * chain transactions.
 * 
 */

#include "pbaas/notarization.h"
#include "pbaas/crosschainrpc.h"
#include "rpc/pbaasrpc.h"
#include "cc/CCinclude.h"
#include "komodo_globals.h"

#include <assert.h>

using namespace std;

extern uint160 VERUS_CHAINID;
extern string PBAAS_HOST;
extern string PBAAS_USERPASS;
extern int32_t PBAAS_PORT;

CPBaaSNotarization::CPBaaSNotarization(const CTransaction &tx, bool validate)
{
    // the PBaaS notarization itself is a combination of proper inputs, one output, and
    // a sequence of opret chain objects as proof of the output values on the chain to which the
    // notarization refers, the opret can be reconstructed from chain data in order to validate
    // the txid of a transaction that does not contain the opret itself
    
    // a notarization must have notarization output that spends to the address indicated by the 
    // ChainID, an opret, that there is only one, and that it can be properly decoded to a notarization 
    // output, whether or not validate is true
    bool notarizationFound = false;
    bool error = false;
    for (auto out : tx.vout)
    {
        uint32_t ecode;
        if (out.scriptPubKey.IsPayToCryptoCondition(&ecode))
        {
            if (ecode == EVAL_ACCEPTEDNOTARIZATION || ecode == EVAL_EARNEDNOTARIZATION)
            {
                if (notarizationFound)
                {
                    error = true;
                    mmrRoot.SetNull();
                }
                else
                {
                    COptCCParams p;
                    notarizationFound = true;

                    // TODO: this only tells us it is a pay to CC tx. we need to validate ourselves after
                    if (!IsPayToCryptoCondition(out.scriptPubKey, p, *this))
                    {
                        mmrRoot.SetNull();
                    }
                }
            }
        }
    }

    // the following rules are enforced if validate is true:
    // 1) must either have the chain definition output on output 0 or spend the notarization
    //    thread for this chain.
    // 2) must spend and distribute funds from the last validated notarization and invalidate
    //    all invalidated notarizations, returning their payout to the notarization pool
    // 3) all values in notarization must match the opret
    // 4) all referenced objects must be consistent with this chain
    // 5) validation output must either be spent as validated or unspent
    //
    if (validate)
    {
        
    }
}

CNotarizationFinalization::CNotarizationFinalization(const CTransaction &tx, bool validate)
{
    bool found = false;
    bool error = false;
    for (auto out : tx.vout)
    {
        uint32_t ecode;
        if (out.scriptPubKey.IsPayToCryptoCondition(&ecode))
        {
            if (ecode == EVAL_FINALIZENOTARIZATION)
            {
                if (found)
                {
                    error = true;
                    confirmedInput = -1;
                }
                else
                {
                    COptCCParams p;
                    found = true;

                    if (!IsPayToCryptoCondition(out.scriptPubKey, p, *this))
                    {
                        confirmedInput = -1;
                    }
                }
            }
        }
    }

    if (validate)
    {
        
    }
}

// this gets the last notarization of this chain from the chain passed
// we pass chain name, so that we can access the chain information
bool GetLastMatchingNotarization(string &chainID)
{
    // make sure we have a valid host and credentials
    if (!PBAAS_HOST.size() || !PBAAS_USERPASS.size())
    {
        return false;
    }

    // get chain notarization data, see which of the notarizations match our latest notarization,
    // get the cross transaction, and make a notarization transaction to put into a block

    CKeyID keyID(CrossChainRPCData::GetConditionID(chainID, EVAL_ACCEPTEDNOTARIZATION));
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    if (GetAddressIndex(keyID, 0, addressIndex))
    {
        // iterate backwards until we find a notarization that we agree with
        for (auto it = addressIndex.end(); it != addressIndex.begin(); it--)
        {
            CTransaction notarization;
            uint256 blkHash;
            COptCCParams p;

            if (myGetTransaction(it->first.txhash, notarization, blkHash))
            {
                CPBaaSNotarization pbn;
                if (IsPayToCryptoCondition(notarization.vout[it->first.txindex].scriptPubKey, p, pbn) && (p.evalCode == EVAL_EARNEDNOTARIZATION))
                {
                    // interpret this notarization and determine if we agree

                }
            }
            else
            {
                // failure to read a tx means that we will not successfully determine
                // the latest we agree with
                return false;
            }
        }
    }
}

// This creates a notarization that will be in the current block and use the prevMMR to prove the block before us
// we refer to the transactions on the Verus chain and on our chain with which we agree, and if we have added the
// 10th validation to a notarization in our lineage, we finalize it as validated and finalize any conflicting notarizations
// as invalidated.
bool CreateEarnedNotarization(CMutableTransaction &mnewTx, CTransaction &lastTx, CTransaction &crossTx, int32_t height, uint256 &prevMMR)
{
    // we can only create a notarization if there is an available Verus chain
    CPBaaSMergeMinedChainData pmmcd;
    if (!ConnectedChains.GetChainInfo(VERUS_CHAINID, pmmcd))
    {
        return false;
    }

    UniValue params(UniValue::VARR);
    params.push_back(VERUS_CHAINID.GetHex());

    CChainNotarizationData cnd;

    UniValue txidArr(UniValue::VARR);

    if (GetNotarizationData(VERUS_CHAINID, EVAL_EARNEDNOTARIZATION, cnd))
    {
        // make an array of all possible txids on this chain
        for (auto it : cnd.vtx)
        {
            txidArr.push_back(it.first.GetHex());
        }
    }

    params.push_back(txidArr);

    auto result = RPCCall("getcrossnotarization", params, pmmcd.rpcHost, pmmcd.rpcPort, pmmcd.rpcUserPass);

    // if no error, prepare notarization
    auto uv1 = find_value(result, "crosstxid");
    auto uv2 = find_value(result, "txid");
    auto uv3 = find_value(result, "rawtx");
    auto uv4 = find_value(result, "newtx");

    // if we passed no prior notarizations, the crosstxid returned can be null
    if ((!uv1.isStr() && (cnd.vtx.size() != 0)) || !uv2.isStr() || !uv3.isStr() || !uv4.isStr())
    {
        return false;
    }

    uint256 lastNotarizationID = uint256(ParseHex(uv1.get_str()));
    uint256 crossNotarizationID = uint256(ParseHex(uv2.get_str()));
    if (lastNotarizationID.IsNull() || crossNotarizationID.IsNull() || !DecodeHexTx(crossTx, uv3.get_str()))
    {
        return false;
    }

    CTransaction newTx;
    if (!DecodeHexTx(newTx, uv4.get_str()))
    {
        return false;
    }

    CPBaaSNotarization crossNotarizaton(crossTx);
    CPBaaSChainDefinition chainDef(crossTx);
    if (crossNotarizaton.prevNotarization.IsNull() && !chainDef.IsValid())
    {
        // must either have a prior notarization or be the definition
        return false;
    }

    // we have more work to do on it
    mnewTx = CMutableTransaction(newTx);
    CPBaaSNotarization pbn;

    int i;
    for (i = 0; i < mnewTx.vout.size(); i++)
    {
        COptCCParams p;
        uint32_t ecode;
        if (mnewTx.vout[i].scriptPubKey.IsPayToCryptoCondition(&ecode) &&
            ecode == EVAL_EARNEDNOTARIZATION && 
            IsPayToCryptoCondition(mnewTx.vout[i].scriptPubKey, p, pbn))
        {
            break;
        }
    }

    // if i == vout.size(), we didn't find the expected notarization, should never happen
    if (!pbn.IsValid() || pbn.nVersion != PBAAS_VERSION)
    {
        return false;
    }

    pbn.prevNotarization = lastNotarizationID;
    if (lastNotarizationID.IsNull())
    {
        pbn.prevHeight = 0;
    }
    else
    {
        uint256 hblk;
        if (!GetTransaction(lastNotarizationID, lastTx, hblk, true))
        {
            return false;
        }
        pbn.prevHeight = mapBlockIndex[hblk]->GetHeight();
    }

    // determine all finalized transactions that should be spent as input
    set<int32_t> finalized;
    int32_t confirmedIdx = -1;

    // now, create inputs from lastTx and the finalization outputs that we either confirm or invalidate
    for (int j = 0; j < cnd.forks.size(); j++)
    {
        int k;
        for (k = cnd.forks[j].size() - 1; k >= 0; k--)
        {
            // the first instance of the prior notarization we find caps the prior fork we are confirming
            if (cnd.vtx[cnd.forks[j][k]].first == lastNotarizationID)
            {
                // the only way to get to greater than 10 is by breaking the rules, as the first
                // entry should be the earliest notarization or the last confirmed
                assert(k <= 10);

                if (k == 10)
                {
                    confirmedIdx = cnd.forks[j][1];
                    // if we would add the 10th confirmation to the second in this fork, we are confirming 
                    // a new notarization, spend it's finalization output and all those that disagree with it
                    // the only chains that are confirmed to disagree will have a different index in the
                    // second position, which is the one we are confirming
                    for (int l = 0; l < cnd.forks.size(); l++)
                    {
                        // if another fork branches at the confirmed notarization, the entire fork
                        // is invalid, spend all its finalization outputs
                        if (l != j && cnd.forks[l][1] != confirmedIdx)
                        {
                            for (int m = 1; m < cnd.forks[l].size(); m++)
                            {
                                // put indexes of all orphans into the set
                                finalized.insert(cnd.forks[l][m]);
                            }
                        }
                    }
                    break;
                }
            }
        }
        // if we short circuited by confirmation, short circuit here too
        if (k >= 0)
        {
            break;
        }
    }

    // now, we should spend the last notarization output and all finalization outputs in the finalized set
    // first, we need to get the outpoint for the notarization, and each finalization as well
    uint32_t j;
    for (j = 0; j < lastTx.vout.size(); j++)
    {
        uint32_t code;
        if (lastTx.vout[j].scriptPubKey.IsPayToCryptoCondition(&code) && code == EVAL_EARNEDNOTARIZATION)
        {
            break;
        }
    }

    // either we have no last, or we found its notarization output
    assert(lastNotarizationID.IsNull() || j < lastTx.vout.size());

    // if this isn't the first notarization, setup inputs
    if (lastNotarizationID.IsNull())
    {
        // it is currently only valid to make the first notarization in block #1 on a PBaaS chain
        if (chainActive.LastTip() != NULL && chainActive.LastTip()->GetHeight() > 0)
        {
            return false;
        }
    }
    else
    {
        mnewTx.vin.push_back(CTxIn(lastNotarizationID, j, CScript()));

        for (auto nidx : finalized)
        {
            // we need to reload all transactions and get their finalization outputs
            // this could be made more efficient by keeping them earlier or standardizing output numbers
            CTransaction orphanTx;
            uint256 hblk;
            if (!GetTransaction(cnd.vtx[nidx].first, orphanTx, hblk, true))
            {
                // if this fails, we can't follow consensus and must fail
                return false;
            }
            int k;
            for (k = 0; k < lastTx.vout.size(); k++)
            {
                uint32_t code;
                if (orphanTx.vout[k].scriptPubKey.IsPayToCryptoCondition(&code) && code == EVAL_FINALIZENOTARIZATION)
                {
                    break;
                }
            }
            assert(k < orphanTx.vout.size());

            // spend all of them
            mnewTx.vin.push_back(CTxIn(cnd.vtx[nidx].first, k, CScript()));
        }
    }

    // we need our earned notarization and finalization outputs, divide outputs evenly, as none of the earned notarizations
    // are paid on this chain

    CCcontract_info CC;
    CCcontract_info *cp;
    vector<CTxDestination> vKeys;

    // make the earned notarization output
    cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);
    // need to be able to send this to EVAL_PBAASDEFINITION address as a destination, locked by the default pubkey
    CPubKey pk = CPubKey(std::vector<unsigned char>(CC.CChexstr, CC.CChexstr + strlen(CC.CChexstr)));

    vKeys.push_back(CTxDestination(CKeyID(CrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, EVAL_EARNEDNOTARIZATION))));

    // update crypto condition with final notarization output data
    mnewTx.vout.push_back(MakeCC1of1Vout(EVAL_EARNEDNOTARIZATION, PBAAS_MINNOTARIZATIONOUTPUT, pk, vKeys, pbn));

    
    // make the finalization output
    cp = CCinit(&CC, EVAL_FINALIZENOTARIZATION);
    // need to be able to send this to EVAL_PBAASDEFINITION address as a destination, locked by the default pubkey
    pk = CPubKey(std::vector<unsigned char>(CC.CChexstr, CC.CChexstr + strlen(CC.CChexstr)));

    vKeys[0] = CTxDestination(CKeyID(CrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, EVAL_FINALIZENOTARIZATION)));

    // update crypto condition with final notarization output data
    mnewTx.vout.push_back(MakeCC1of1Vout(EVAL_FINALIZENOTARIZATION, PBAAS_MINNOTARIZATIONOUTPUT, pk, vKeys, pbn));

    return true;
}

// This creates a notarization that validates its acceptance as conforming to all conditions
bool CreateAcceptedNotarization(vector<CMutableTransaction> &vmtx, CTxOut &lastNotarizationOutput, vector<CTransaction> crossNotarizations)
{

}

/*
 * Validates a notarization output spend by ensuring that the spending transaction fulfills all requirements.
 * to accept an earned notarization as valid on the Verus blockchain, it must prove a transaction on the alternate chain, which is 
 * either the original chain definition transaction, which CAN and MUST be proven ONLY in block 1, or the latest notarization transaction 
 * on the alternate chain that represents an accurate MMR for this chain.
 * In addition, any accepted notarization must fullfill the following requirements:
 * 1) Must prove either a PoS block from the alternate chain or a merge mined block that is owned by the submitter and in either case, 
 *    the block must be exactly 8 blocks behind the submitted MMR used for proof.
 * 2) Must prove a chain definition tx and be block 1 or asserts a previous, valid MMR for the notarizing
 *    chain and properly prove objects using that MMR.
 * 3) Must spend the main notarization thread as well as any finalization outputs of either valid or invalid prior
 *    notarizations, and any unspent notarization contributions for this era. May also spend other inputs.
 * 4) Must output:
 *      a) finalization output of the expected reward amount, which will be sent when finalized
 *      b) normal output of reward from validated/finalized input if present, 50% to recipient / 50% to block miner less miner fee this tx
 *      c) main notarization thread output with remaining funds, no other output or fee deduction
 * 
 */
bool ValidateAcceptedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // this validates the spending transaction
    // first and foremost, check the following two things:
    // 1. It represents a valid PoS or merge mined block on the other chain, and contains the header in the opret
    // 2. The MMR and proof provided for the currently asserted block can prove the provided header. The provided
    //    header can prove the last block referenced.

    // if those are true, then check if we have all relevant inputs, including that we properly finalize all necessary transactions
    // we will jump back 10 transactions, if there are that many in our thread, validate the 10th, invalidate
    // any notarizations that do not derive from that notarization, and spend as inputs
}

/*
 * Ensures that a spend in an earned notarization of either an OpRet support transaction or summary notarization
 * are valid with respect to this chain. Any transaction that spends from an opret trasaction is either disconnected,
 * or contains the correct hashes of each object and transaction data except for the opret, which can be validated by
 * reconstructing the opret from the hashes on the other chain and verifying that it hashes to the same input value. This
 * enables full validation without copying redundant data back to its original chain.
 * 
 * In addition, each earned notarization must reference the last earned notarization with which it agrees and prove the last
 * accepted notarization on the alternate chain with the latest MMR. The earned notarization will not be accepted if there is
 * a later notarization that agrees with it already present in the alternate chain when it is submitted. 
 * 
 */
bool ValidateEarnedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{

}

/*
 * Ensures that the finalization, either as validated or orphaned, is determined by
 * 10 confirmations, either of this transaction, or of an alternate transaction on the chain that we do not derive
 * from. If the former, then this should be asserted to be validated, otherwise, it should be asserted to be invalidated.
 *  
 */
bool ValidateFinalizeNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{

}

// ensures that all cryptographically verifiable proofs and rules of notarization are verified
bool ValidateNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{

}

