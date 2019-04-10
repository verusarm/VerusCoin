/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS initialization, notarization, and cross-chain token
 * transactions and enabling liquid or non-liquid tokens across the
 * Verus ecosystem.
 * 
 */

#include "pbaas/pbaas.h"
#include "pbaas/notarization.h"
#include "rpc/pbaasrpc.h"
#include "pbaas/crosschainrpc.h"
#include "base58.h"

using namespace std;

CConnectedChains ConnectedChains;
CPBaaSChainDefinition ThisChainDefinition;

bool IsVerusActive()
{
    return (strcmp(ASSETCHAINS_SYMBOL, "VRSC") == 0 || strcmp(ASSETCHAINS_SYMBOL, "VRSCTEST") == 0);
}

// this adds an opret to a mutable transaction and returns the voutnum if it could be added
int32_t AddOpRetOutput(CMutableTransaction &mtx, const CScript &opRetScript)
{
    if (opRetScript.IsOpReturn() && opRetScript.size() <= MAX_OP_RETURN_RELAY)
    {
        CTxOut vOut = CTxOut();
        vOut.scriptPubKey = opRetScript;
        vOut.nValue = 0;
        mtx.vout.push_back(vOut);
        return mtx.vout.size() - 1;
    }
    else
    {
        return -1;
    }
}

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
uint256 GetChainObjectHash(const CBaseChainObject &bo)
{
    union {
        const CChainObject<CBlockHeader> *pNewHeader;
        const CChainObject<CTransaction> *pNewTx;
        const CChainObject<CMerkleBranch> *pNewProof;
        const CChainObject<CHeaderRef> *pNewHeaderRef;
        const CChainObject<CTransactionRef> *pNewTxRef;
        const CChainObject<COpRetRef> *pNewOpRetRef;
        const CBaseChainObject *retPtr;
    };

    retPtr = &bo;

    switch(bo.objectType)
    {
        case CHAINOBJ_HEADER:
            return pNewHeader->GetHash();

        case CHAINOBJ_TRANSACTION:
            return pNewTx->GetHash();

        case CHAINOBJ_PROOF:
            return pNewProof->GetHash();

        case CHAINOBJ_HEADER_REF:
            return pNewHeaderRef->GetHash();

        case CHAINOBJ_TRANSACTION_REF:
            return pNewTxRef->GetHash();

        case CHAINOBJ_OPRET_REF:
            return pNewOpRetRef->GetHash();
    }
    return uint256();
}

// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{

}

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{

}

// used to validate a specific service reward based on the spending transaction
bool ValidateServiceReward(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{

}

// used as a proxy token output for a reserve currency on its fractional reserve chain
bool ValidateReserveOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{

}

// used to convert a fractional reserve currency into its reserve and back 
bool ValidateReserveExchange(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{

}

// used for distribution of premine
bool ValidatePremineOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{

}

/*
 * Verifies that the input objects match the hashes and returns the transaction.
 * 
 * If the opRetTx has the op ret, this calculates based on the actual transaction and
 * validates the hashes. If the opRetTx does not have the opRet itself, this validates
 * by ensuring that all objects are present on this chain, composing the opRet, and
 * ensuring that the transaction then hashes to the correct txid.
 * 
 */
bool ValidateOpretProof(CScript &opRet, COpRetProof &orProof)
{
    // enumerate through the objects and validate that they are objects of the expected type that hash
    // to the value expected. return true if so
        
}

int8_t ObjTypeCode(COpRetProof &obj)
{
    return CHAINOBJ_OPRETPROOF;
}

int8_t ObjTypeCode(CBlockHeader &obj)
{
    return CHAINOBJ_HEADER;
}

int8_t ObjTypeCode(CMerkleBranch &obj)
{
    return CHAINOBJ_PROOF;
}

int8_t ObjTypeCode(CTransaction &obj)
{
    return CHAINOBJ_TRANSACTION;
}

int8_t ObjTypeCode(CHeaderRef &obj)
{
    return CHAINOBJ_HEADER_REF;
}

int8_t ObjTypeCode(CTransactionRef &obj)
{
    return CHAINOBJ_TRANSACTION_REF;
}

int8_t ObjTypeCode(COpRetRef &obj)
{
    return CHAINOBJ_OPRET_REF;
}

// this adds an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
CScript StoreOpRetArray(std::vector<const CBaseChainObject *> &objPtrs)
{
    CScript vData;
    CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
    bool error = false;

    for (auto pobj : objPtrs)
    {
        if (!DehydrateChainObject(s, pobj))
        {
            error = true;
            break;
        }
    }

    std::vector<unsigned char> vch(s.begin(), s.end());

    vData << OPRETTYPE_OBJECTARR << vch;
    vch = std::vector<unsigned char>(vData.begin(), vData.end());
    return CScript() << OP_RETURN << vch;
}

std::vector<CBaseChainObject *> RetrieveOpRetArray(const CScript &opRetScript)
{
    std::vector<unsigned char> vch;
    std::vector<CBaseChainObject *> vRet;
    if (opRetScript.IsOpReturn() && GetOpReturnData(opRetScript, vch) && vch.size() > 0)
    {
        CDataStream s = CDataStream(vch, SER_NETWORK, PROTOCOL_VERSION);

        CBaseChainObject *pobj;
        while (!s.empty() && (pobj = RehydrateChainObject(s)))
        {
            vRet.push_back(pobj);
        }
    }
    return vRet;
}

CNodeData::CNodeData(UniValue &obj)
{
    networkAddress = find_value(obj, "networkaddress").get_str();
    paymentAddress = GetDestinationID(DecodeDestination(find_value(obj, "paymentaddress").get_str()));
}

UniValue CNodeData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("networkaddress", networkAddress));
    obj.push_back(Pair("paymentaddress", CBitcoinAddress(paymentAddress).ToString()));
    return obj;
}

CPBaaSChainDefinition::CPBaaSChainDefinition(UniValue &obj)
{
    nVersion = find_value(obj, "version").get_int();
    name = find_value(obj, "name").get_str();
    address = find_value(obj, "foundersaddress").get_str();
    premine = find_value(obj, "premine").get_int64();
    conversion = find_value(obj, "conversionfactor").get_int64();
    launchfee = find_value(obj, "launchfactor").get_int64();
    startBlock = find_value(obj, "startblock").get_int64();
    endBlock = find_value(obj, "endblock").get_int64();

    auto vEras = find_value(obj, "eras").getValues();
    eras = vEras.size();

    for (auto era : vEras)
    {
        rewards.push_back(find_value(obj, "initialreward").get_int64());
        rewardsDecay.push_back(find_value(obj, "rewarddecay").get_int64());
        halving.push_back(find_value(obj, "halvingperiod").get_int64());
        eraEnd.push_back(find_value(obj, "eraend").get_int64());
        eraOptions.push_back(find_value(obj, "eraoptions").get_int64());
    }

    firstBlockReward = find_value(obj, "firstblockreward").get_int64();
    notarizationReward = find_value(obj, "notarizationreward").get_int64();

    auto nodeVec = find_value(obj, "nodes").getValues();
    for (auto node : nodeVec)
    {
        nodes.push_back(CNodeData());
    }
}

CPBaaSChainDefinition::CPBaaSChainDefinition(const CTransaction &tx, bool validate)
{
    bool definitionFound = false;
    nVersion = PBAAS_VERSION_INVALID;
    for (auto out : tx.vout)
    {
        uint32_t ecode;
        if (out.scriptPubKey.IsPayToCryptoCondition(&ecode))
        {
            if (ecode == EVAL_PBAASDEFINITION)
            {
                if (definitionFound)
                {
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else
                {
                    COptCCParams p;
                    definitionFound = true;
                    if (!IsPayToCryptoCondition(out.scriptPubKey, p, *this))
                    {
                        nVersion = PBAAS_VERSION_INVALID;
                    }
                }
            }
        }
    }

    if (validate)
    {
        
    }
}

uint160 CPBaaSChainDefinition::GetChainID(std::string name)
{
    const char *chainName = name.c_str();
    uint256 chainHash = Hash(chainName, chainName + strlen(chainName));
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CPBaaSChainDefinition::GetConditionID(int32_t condition)
{
    uint160 cid = GetChainID(name);
    const char *condStr = itostr(condition).c_str();
    uint256 chainHash = Hash(condStr, condStr + strlen(condStr), (char *)&cid, ((char *)&cid) + sizeof(cid));
    return Hash160(chainHash.begin(), chainHash.end());
}

UniValue CPBaaSChainDefinition::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int64_t)nVersion));
    obj.push_back(Pair("name", name));
    obj.push_back(Pair("foundersaddress", address));
    obj.push_back(Pair("premine", (int64_t)premine));
    obj.push_back(Pair("conversionfactor", (int64_t)conversion));
    obj.push_back(Pair("launchfactor", (int64_t)launchfee));
    obj.push_back(Pair("conversion", (double)conversion / 100000000));
    obj.push_back(Pair("launchfeepercent", ((double)launchfee / 100000000) * 100));
    obj.push_back(Pair("startblock", (int64_t)startBlock));
    obj.push_back(Pair("endblock", (int64_t)endBlock));

    UniValue eraArr(UniValue::VARR);
    for (int i = 0; i < eras; i++)
    {
        UniValue era(UniValue::VOBJ);
        era.push_back(Pair("initialreward", rewards.size() > i ? rewards[i] : (int64_t)0));
        era.push_back(Pair("rewarddecay", rewardsDecay.size() > i ? rewardsDecay[i] : (int64_t)0));
        era.push_back(Pair("halvingperiod", halving.size() > i ? halving[i] : (int64_t)0));
        era.push_back(Pair("eraend", eraEnd.size() > i ? eraEnd[i] : (int64_t)0));
        era.push_back(Pair("eraoptions", eraOptions.size() > i ? eraOptions[i] : (int64_t)0));
        eraArr.push_back(era);
    }
    obj.push_back(Pair("eras", eraArr));

    obj.push_back(Pair("firstblockreward", (int64_t)firstBlockReward));
    obj.push_back(Pair("notarizationreward", (int64_t)notarizationReward));

    UniValue nodeArr(UniValue::VARR);
    for (auto node : nodes)
    {
        nodeArr.push_back(node.ToUniValue());
    }
    obj.push_back(Pair("nodes", nodeArr));

    return obj;
}

// adds the nodes as well
void SetThisChain(UniValue &chainDefinition)
{
    ThisChainDefinition = CPBaaSChainDefinition(chainDefinition);
    // set all command line parameters into mapArgs from chain definition
    for (auto node : ThisChainDefinition.nodes)
    {
        AddOneShot(node.networkAddress);
    }
}

// ensures that the chain definition is valid and that there are no other definitions of the same name
// that have been confirmed.
bool ValidateChainDefinition(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // the chain definition output can be spent when the chain is at the end of its life and only then
    // TODO
    return false;
}

// ensures that the chain definition is valid and that there are no other definitions of the same name
// that have been confirmed.
bool CheckChainDefinitionOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // checked before a chain definition output script is accepted as a valid transaction

    // basics - we need a chain definition transaction to kick off a PBaaS chain. it must have:
    // 1) valid chain definition output with parameters in proper ranges and no duplicate name
    // 2) notarization output with conformant values
    // 3) finalization output
    // 3) notarization funding
    //

    // get the source transaction
    uint256 blkHash;
    CTransaction thisTx;
    if (!myGetTransaction(tx.vin[nIn].prevout.hash, thisTx, blkHash))
    {
        LogPrintf("failed to retrieve transaction %s\n", tx.vin[nIn].prevout.hash.GetHex().c_str());
        return false;
    }

    CPBaaSChainDefinition chainDef(thisTx, true);
    CPBaaSNotarization notarization(thisTx, true);
    CNotarizationFinalization finalization(thisTx, true);

    if (!chainDef.IsValid() || !notarization.IsValid() || finalization.IsValid())
    {
        LogPrintf("transaction specified, %s, must have valid chain definition, notarization, and finaization outputs\n", tx.vin[nIn].prevout.hash.GetHex().c_str());
        return false;
    }

    CPBaaSChainDefinition prior;
    // this ensures that there is no other definition of the same name already on the blockchain
    if (!GetChainDefinition(chainDef.name, prior))
    {
        LogPrintf("PBaaS chain with the name %s already exists\n", chainDef.name.c_str());
        return false;
    }

    return true;
}

bool CConnectedChains::RemoveMergedBlock(uint160 chainID)
{
    LOCK(cs_mergemining);
    auto chainIt = mergeMinedChains.find(chainID);
    if (chainIt != mergeMinedChains.end())
    {
        arith_uint256 target;
        target.SetCompact(chainIt->second.block.nBits);
        for (auto removeRange = mergeMinedTargets.equal_range(target); removeRange.first != removeRange.second; removeRange.first++)
        {
            // make sure we don't just match by target
            if (removeRange.first->second->GetChainID() == chainID)
            {
                mergeMinedTargets.erase(removeRange.first);
                break;
            }
        }
        mergeMinedChains.erase(chainID);
        dirtyCounter++;

        // if we get to 0, give the thread a kick to stop waiting for mining
        if (!mergeMinedChains.size())
        {
            sem_submitthread.post();
        }
    }
}

// remove merge mined chains added and not updated since a specific time
uint32_t CConnectedChains::PruneOldChains(uint32_t pruneBefore)
{
    vector<uint160> toRemove;

    LOCK(cs_mergemining);
    for (auto blkData : mergeMinedChains)
    {
        if (blkData.second.block.nTime < pruneBefore)
        {
            toRemove.push_back(blkData.first);
        }
    }

    for (auto id : toRemove)
    {
        RemoveMergedBlock(id);
    }
}

// adds or updates merge mined blocks
// returns false if failed to add
bool CConnectedChains::AddMergedBlock(CPBaaSMergeMinedChainData &blkData)
{
    bool blockSet = false;
    int idx = -1;
    // determine if we should replace one or add to the merge mine vector
    {
        LOCK(cs_mergemining);

        uint160 cID = blkData.GetChainID();
        auto it = mergeMinedChains.find(cID);
        if (it != mergeMinedChains.end())
        {
            // replace data
            it->second = blkData;
        }
        else
        {
            arith_uint256 target;
            target.SetCompact(blkData.block.nBits);
            mergeMinedTargets.insert(make_pair(target, &(mergeMinedChains.insert(make_pair(cID, blkData)).first->second)));
        }
        dirtyCounter++;
    }
}

bool CConnectedChains::GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData)
{
    {
        LOCK(cs_mergemining);
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            rpcChainData = (CRPCChainData)chainIt->second;
            return true;
        }
        return false;
    }
}

// this returns a pointer to the data without copy and assumes the lock is held
CPBaaSMergeMinedChainData *CConnectedChains::GetChainInfo(uint160 chainID)
{
    {
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            return &chainIt->second;
        }
        return NULL;
    }
}

// submit all blocks that are present in the header and where the target is met
vector<pair<string, UniValue>> CConnectedChains::SubmitQualifiedBlocks(const CBlockHeader &bh)
{
    std::set<uint160> inHeader;
    arith_uint256 blkHash = UintToArith256(bh.GetHash());

    vector<UniValue> toSubmit;
    vector<CRPCChainData> chainData;
    vector<pair<string, UniValue>>  results;

    CPBaaSBlockHeader pbh;

    // loop through the existing PBaaS chain ids in the header and add them to ax set
    for (uint32_t i = 0; bh.GetPBaaSHeader(pbh, i); i++)
    {
        inHeader.insert(pbh.chainID);
    }

    {
        LOCK(cs_mergemining);
        for (auto chainIt = mergeMinedTargets.lower_bound(blkHash); chainIt != mergeMinedTargets.end(); chainIt++)
        {
            uint160 chainID = chainIt->second->GetChainID();
            if (inHeader.count(chainID))
            {
                // get block, remove the block from merged headers, replace header, and submit
                CBlock &block = chainIt->second->block;

                CPBaaSPreHeader preHeader(block);

                *(CBlockHeader *)&block = bh;

                block.hashPrevBlock = preHeader.hashPrevBlock;
                block.hashFinalSaplingRoot = preHeader.hashFinalSaplingRoot;
                block.nBits = preHeader.nBits;
                block.nNonce = preHeader.nNonce;
                block.hashMerkleRoot = preHeader.hashMerkleRoot;

                // check if it can be submitted, if not, there is some error, or the block was updated since
                // the win
                arith_uint256 target;
                target.SetCompact(block.nBits);
                if (UintToArith256(block.GetHash()) > target)
                {
                    LogPrintf("Unable to submit merge mined block for %s chain\n", chainIt->second->chainDefinition.name.c_str());
                    continue;
                }

                // once it is going to be submitted, remove it until it is added again
                RemoveMergedBlock(chainID);

                UniValue submitParams(UniValue::VARR);

                // TODO: setup one submission worth of UniValue parameters

                // push completed submit parameters and chain data
                toSubmit.push_back(submitParams);
                chainData.push_back(*chainIt->second);
            }
        }
    }

    for (int i = 0; i < toSubmit.size(); i++)
    {
        results.push_back(make_pair(chainData[i].chainDefinition.name, 
                                    RPCCall("submitblock", toSubmit[i], chainData[i].rpcUserPass, chainData[i].rpcPort, chainData[i].rpcHost)));
    }
    return results;
}

// add all merge mined chain PBaaS headers into the blockheader and return the total number
uint32_t CConnectedChains::CombineBlocks(CBlockHeader &bh)
{
    vector<uint160> inHeader;
    vector<UniValue> toCombine;
    arith_uint256 blkHash = UintToArith256(bh.GetHash());
    
    CPBaaSBlockHeader pbh;

    for (uint32_t i = 0; bh.GetPBaaSHeader(pbh, i); i++)
    {
        inHeader.push_back(pbh.chainID);
    }

    // loop through the existing PBaaS chain ids in the header
    // remove any not either this Chain ID or in our local collection and then add all that are present
    for (uint32_t i = 0; i < inHeader.size(); i++)
    {
        if (inHeader[i] != ASSETCHAINS_CHAINID && !mergeMinedChains.count(inHeader[i]))
        {
            bh.DeletePBaaSHeader(i);
        }
    }

    {
        LOCK(cs_mergemining);
        for (auto chain : mergeMinedChains)
        {
            // get the native PBaaS header for each chain and put it into the
            // header we are given
            uint160 cid = chain.second.GetChainID();
            if (chain.second.block.GetPBaaSHeader(pbh, cid))
            {
                if (!bh.AddUpdatePBaaSHeader(pbh))
                {
                    LogPrintf("Failure to add PBaaS block header for %s chain\n", chain.second.chainDefinition.name.c_str());
                }
            }
        }
    }
    return CConstVerusSolutionVector::GetDescriptor(bh.nSolution).numPBaaSHeaders;
}

bool CConnectedChains::CheckVerusPBaaSVersion(UniValue &rpcGetInfoResult)
{
    bool ret = false;
    UniValue uniVer = find_value(rpcGetInfoResult, "VRSCversion");
    if (uniVer.isStr())
    {
        if (uniVer.get_str() > "0.6")
        {
            ret = true;
        }
    }
    return ret;
}

bool CConnectedChains::CheckVerusPBaaSVersion()
{
    if (IsVerusActive())
    {
        isVerusPBaaSVersion = true;
    }
    else
    {
        // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
        UniValue result;
        result = RPCCallRoot("getinfo", UniValue(UniValue::VARR));
        isVerusPBaaSVersion = CheckVerusPBaaSVersion(result);
    }
}

bool CConnectedChains::IsVerusPBaaSVersion()
{
    return isVerusPBaaSVersion;
}

void CConnectedChains::SubmissionThread()
{
    try
    {
        arith_uint256 lastHash;
        
        {
            LOCK(cs_mergemining);
            lastHash = latestHash;
        }

        // wait for something to checkon, then submit blocks that should be submitted
        while (true)
        {
            if (IsVerusActive())
            {
                if (mergeMinedChains.size() > 0)
                {
                    sem_submitthread.wait();
                    // wait for a new block header win
                    {
                        bool submit = false;
                        {
                            LOCK(cs_mergemining);
                            if (lastHash != latestHash)
                            {
                                submit = true;
                            }
                        }
                        if (submit)
                        {
                            SubmitQualifiedBlocks(latestBlockHeader);
                        }
                    }
                }
                else
                {
                    MilliSleep(500);
                }
            }
            else
            {
                UniValue result;

                // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
                result = RPCCallRoot("getinfo", UniValue(UniValue::VARR));

                UniValue uniVer = find_value(result, "VRSCversion");
                isVerusPBaaSVersion = CheckVerusPBaaSVersion(result);

                sleep(3);
            }

            boost::this_thread::interruption_point();
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("Verus merge mining thread terminated\n");
    }
}

void CConnectedChains::SubmissionThreadStub()
{
    ConnectedChains.SubmissionThread();
}

