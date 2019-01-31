// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/nonce.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "primitives/solutiondata.h"

// this class provides a minimal and compact representation of a merge mined PBaaS header
class CPBaaSBlockHeader
{
public:
    // header
    static const size_t HEADER_SIZE = SOLUTION_PBAAS_HEADER_SIZE;   // serialized PBaaS header size, which is different from a standard block header
    static const size_t ID_OFFSET = 4+32+32+32+4;                   // offset of 32 bit ID in serialized stream
    static const int32_t CURRENT_VERSION = CPOSNonce::VERUS_V2;
    static const int32_t CURRENT_VERSION_MASK = 0x0000ffff;         // for compatibility

    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashFinalSaplingRoot;
    uint32_t nBits;
    uint256 chainID;

    CPBaaSBlockHeader()
    {
        SetNull();
    }

    CPBaaSBlockHeader(const char *pbegin, const char *pend) 
    {
        CDataStream s = CDataStream(pbegin, pend, SER_NETWORK, PROTOCOL_VERSION);
        s >> *this;
    }

    CPBaaSBlockHeader(int32_t ver, const uint256 &hashPrev, const uint256 &hashMerkle, const uint256 &hashFinalSapling, uint32_t bits, const uint256 &cID)
    {
        nVersion = ver;
        hashPrevBlock = hashPrev;
        hashMerkleRoot = hashMerkle;
        hashFinalSaplingRoot = hashFinalSapling;
        nBits = bits;
        chainID = cID;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashFinalSaplingRoot);
        READWRITE(nBits);
        READWRITE(chainID);
    }

    void SetNull()
    {
        nVersion = CURRENT_VERSION;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashFinalSaplingRoot.SetNull();
        nBits = 0;
        chainID.SetNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const size_t HEADER_SIZE = 4+32+32+32+4+4+32;  // excluding Equihash solution
    static const int32_t CURRENT_VERSION = CPOSNonce::VERUS_V1;
    static const int32_t CURRENT_VERSION_MASK = 0x0000ffff; // for compatibility
    static const int32_t VERUS_V2 = CPOSNonce::VERUS_V2;

    static uint256 (CBlockHeader::*hashFunction)() const;

    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashFinalSaplingRoot;
    uint32_t nTime;
    uint32_t nBits;
    CPOSNonce nNonce;
    std::vector<unsigned char> nSolution;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashFinalSaplingRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nSolution);
    }

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashFinalSaplingRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = uint256();
        nSolution.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // returns 0 if not PBaaS, 1 if PBaaS PoW, -1 if PBaaS PoS
    int32_t IsPBaaS()
    {
        if (nVersion == VERUS_V2)
        {
            return CVerusSolutionVector(nSolution).IsPBaaS();
        }
        return 0;
    }

    // returns -1 on failure, upon failure, pbbh is undefined and likely corrupted
    int32_t GetPBaaSHeader(CPBaaSBlockHeader &pbh, const uint256 &cID)
    {
        // find the specified PBaaS header in the solution and return its index if present
        // if not present, return -1
        if (nVersion == VERUS_V2)
        {
            // search in the solution for this header index and return it if found
            CVerusSolutionVector sv = CVerusSolutionVector(nSolution);
            uint32_t descr = sv.Descriptor();
            if (sv.IsPBaaS() == 1)
            {
                uint32_t len = sv.ExtraDataLen();
                unsigned char *ped = sv.ExtraDataPtr();

                // we got some extra data, now check to see if it has the PBaaS header
                for (int i = 0; ((i + 1) * SOLUTION_PBAAS_HEADER_SIZE) <= len; i++)
                {
                    uint256 *pchainID = (uint256 *)(ped + (i * SOLUTION_PBAAS_HEADER_SIZE) + CPBaaSBlockHeader::ID_OFFSET);
                    if (*pchainID == cID)
                    {
                        char *pch = (char *)ped + i * SOLUTION_PBAAS_HEADER_SIZE;
                        CDataStream s = CDataStream(pch, pch + SOLUTION_PBAAS_HEADER_SIZE, SER_NETWORK, PROTOCOL_VERSION);
                        pbh.Unserialize(s);
                        if (!pbh.IsNull())
                        {
                            return i;
                        }
                    }
                }
            }
        }
        return -1;
    }

    // returns false on failure to read data
    bool GetPBaaSHeader(CPBaaSBlockHeader &pbh, uint32_t idx)
    {
        // search in the solution for this header index and return it if found
        CVerusSolutionVector sv = CVerusSolutionVector(nSolution);
        uint32_t descr = sv.Descriptor();
        uint32_t len = sv.ExtraDataLen();
        int pbType;
        if (nVersion == VERUS_V2 && sv.IsPBaaS() == 1 && ((idx + 1) * SOLUTION_PBAAS_HEADER_SIZE) <= len)
        {
            unsigned char *ped = sv.ExtraDataPtr();
            char *pch = (char *)ped + idx * SOLUTION_PBAAS_HEADER_SIZE;
            CDataStream s = CDataStream(pch, pch + SOLUTION_PBAAS_HEADER_SIZE, SER_NETWORK, PROTOCOL_VERSION);
            pbh.Unserialize(s);
            return true;
        }
        return false;
    }

    // this can save a new header into an empty space or update an existing header
    bool SavePBaaSHeader(uint32_t idx, CPBaaSBlockHeader &pbh)
    {
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();
        int ix;

        if (IsPBaaS() == 1 && pbh.nBits && !pbh.chainID.IsNull() && (((ix = GetPBaaSHeader(pbbh, pbh.chainID)) == -1) || ix == idx))
        {
            // make sure the place it is going is the same or valid and empty
            if (ix != -1 || (GetPBaaSHeader(pbbh, idx) && pbbh.IsNull()))
            {
                CVerusSolutionVector sv = CVerusSolutionVector(nSolution);

                // this serializes the specified data and stores it in the indexed location of the header solution
                CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
                pbh.Serialize(s);

                // write serialized data to the solution
                std::memcpy(sv.ExtraDataPtr() + (idx * SOLUTION_PBAAS_HEADER_SIZE), std::vector<unsigned char>(s.begin(), s.end()).data(), SOLUTION_PBAAS_HEADER_SIZE);
                return true;
            }
        }
        return false;
    }

    bool UpdatePBaaSHeader(CPBaaSBlockHeader &pbh)
    {
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();
        uint32_t idx;

        // what we are updating, must be present
        if (pbh.nBits && !pbh.chainID.IsNull() && (idx = GetPBaaSHeader(pbbh, pbh.chainID)) != -1)
        {
            CVerusSolutionVector sv = CVerusSolutionVector(nSolution);

            // this serializes the specified data and stores it in the indexed location of the header solution
            CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
            pbh.Serialize(s);

            // write serialized data to the solution
            std::memcpy(sv.ExtraDataPtr() + (idx * SOLUTION_PBAAS_HEADER_SIZE), std::vector<unsigned char>(s.begin(), s.end()).data(), SOLUTION_PBAAS_HEADER_SIZE);
            return true;
        }
        return false;
    }

    void DeletePBaaSHeader(uint32_t idx)
    {
        // this frees a specific slot in the array of PBaaS headers, so it may be used for another chain's header
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();
        CVerusSolutionVector sv = CVerusSolutionVector(nSolution);
        uint32_t len = sv.ExtraDataLen();
        uint32_t descr = sv.Descriptor();
        if (nVersion == VERUS_V2 && sv.IsPBaaS() == 1 && (((idx + 1) * SOLUTION_PBAAS_HEADER_SIZE) <= len))
        {
            // write serialized data to the solution
            CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
            pbbh.Serialize(s);
            std::memcpy(sv.ExtraDataPtr() + (idx * SOLUTION_PBAAS_HEADER_SIZE), std::vector<unsigned char>(s.begin(), s.end()).data(), SOLUTION_PBAAS_HEADER_SIZE);
        }
    }

    int32_t AddPBaaSHeader(CPBaaSBlockHeader &pbh)
    {
        // allocates and reserves a spot in the PBaaS header array to be used for a specific header
        // it returns the index of the new, allocated spot, if no spot is available, it returns -1
        // find the specified PBaaS header in the solution and return its index if present
        // if not present, return -1
        if (nVersion == VERUS_V2)
        {
            // search in the solution for this header index and return it if found
            CVerusSolutionVector sv = CVerusSolutionVector(nSolution);
            uint32_t descr = sv.Descriptor();
            if (sv.IsPBaaS() == 1)
            {
                uint32_t len = sv.ExtraDataLen();
                unsigned char *ped = sv.ExtraDataPtr();

                // we got some extra data, now check to see if it has the PBaaS header
                for (int i = 0; ((i + 1) * SOLUTION_PBAAS_HEADER_SIZE) <= len; i++)
                {
                    uint256 *pchainID = (uint256 *)(ped + (i * SOLUTION_PBAAS_HEADER_SIZE) + CPBaaSBlockHeader::ID_OFFSET);
                    if (pchainID->IsNull())
                    {
                        char *pch = (char *)ped + i * SOLUTION_PBAAS_HEADER_SIZE;
                        CDataStream s = CDataStream(pch, pch + SOLUTION_PBAAS_HEADER_SIZE, SER_NETWORK, PROTOCOL_VERSION);
                        CPBaaSBlockHeader pbbh;
                        pbbh.Unserialize(s);
                        if (pbbh.IsNull())
                        {
                            SavePBaaSHeader(i, pbh);
                            return i;
                        }
                    }
                }
            }
        }
        return -1;
    }

    // add the parts of the block header that can be represented by a PBaaS header to the solution
    int32_t AddPBaaSHeader(CBlockHeader &bh, const uint256 &cID)
    {
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader(bh.nVersion, bh.hashPrevBlock, bh.hashMerkleRoot, bh.hashFinalSaplingRoot, bh.nBits, cID);
        return AddPBaaSHeader(pbbh);
    }

    // sets the function of the current in memory header to the PBaaS header's values
    void SetPBaaSHeader(const CPBaaSBlockHeader &pbh)
    {
        // find the specified PBaaS header in the solution and make this header match the chain header passed
        nVersion = pbh.nVersion;
        hashPrevBlock = pbh.hashPrevBlock;
        hashMerkleRoot = pbh.hashMerkleRoot;
        hashFinalSaplingRoot = pbh.hashFinalSaplingRoot;
        nBits = pbh.nBits;
    }

    bool SetPBaaSHeader(const uint256 &cID)
    {
        // find the specified PBaaS header in the solution and make this header match the specified chain's header if present
        // if not present, return false
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();

        if (GetPBaaSHeader(pbbh, cID) != -1)
        {
            SetPBaaSHeader(pbbh);
            return true;
        }
        return false;
    }

    bool SetPBaaSHeader(uint32_t idx)
    {
        // find the specified PBaaS header in the solution and make this header match the specified chain's header if present
        // if not present, return false
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();

        if (GetPBaaSHeader(pbbh, idx))
        {
            SetPBaaSHeader(pbbh);
            return true;
        }
        return false;
    }

    void SetCanonicalPBaaSHeader()
    {
        // this puts the header into a canonical state that will always hash to the same result, regardless of which chain
        // the header is used for. it assumes that the canonical header is always present in position 0
        CPBaaSBlockHeader pbbh = CPBaaSBlockHeader();
        if (GetPBaaSHeader(pbbh, 0))
        {
            SetPBaaSHeader(pbbh);
        }
    }

    uint256 GetHash() const
    {
        return (this->*hashFunction)();
    }

    uint256 GetSHA256DHash() const;
    static void SetSHA256DHash();

    uint256 GetVerusHash() const;
    static void SetVerusHash();

    uint256 GetVerusV2Hash() const;
    static void SetVerusV2Hash();

    bool GetRawVerusPOSHash(uint256 &ret, int32_t nHeight) const;
    bool GetVerusPOSHash(arith_uint256 &ret, int32_t nHeight, CAmount value) const; // value is amount of stake tx
    uint256 GetVerusEntropyHash(int32_t nHeight) const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    uint32_t GetVerusPOSTarget() const
    {
        uint32_t nBits = 0;

        for (const unsigned char *p = nNonce.begin() + 3; p >= nNonce.begin(); p--)
        {
            nBits <<= 8;
            nBits += *p;
        }
        return nBits;
    }

    bool IsVerusPOSBlock() const
    {
        return nNonce.IsPOSNonce(nVersion);
    }

    void SetVerusPOSTarget(uint32_t nBits)
    {
        if (nVersion == VERUS_V2)
        {
            CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);

            arith_uint256 arNonce = UintToArith256(nNonce);

            // printf("before svpt: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            arNonce = (arNonce & CPOSNonce::entropyMask) | nBits;

            // printf("after clear: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            hashWriter << ArithToUint256(arNonce);
            nNonce = CPOSNonce(ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | arNonce));

            // printf(" after svpt: %s\n", nNonce.GetHex().c_str());
        }
        else
        {
            CVerusHashWriter hashWriter = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

            arith_uint256 arNonce = UintToArith256(nNonce);

            // printf("before svpt: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            arNonce = (arNonce & CPOSNonce::entropyMask) | nBits;

            // printf("after clear: %s\n", ArithToUint256(arNonce).GetHex().c_str());

            hashWriter << ArithToUint256(arNonce);
            nNonce = CPOSNonce(ArithToUint256(UintToArith256(hashWriter.GetHash()) << 128 | arNonce));

            // printf(" after svpt: %s\n", nNonce.GetHex().c_str());
        }
    }

    bool SetVersionByHeight(uint32_t height)
    {
        CVerusSolutionVector vsv = CVerusSolutionVector(nSolution);
        if (vsv.SetVersionByHeight(height) && vsv.Version() > 0)
        {
            nVersion = VERUS_V2;
        }
    }

    static uint32_t GetVersionByHeight(uint32_t height)
    {
        if (CVerusSolutionVector::GetVersionByHeight(height) > 0)
        {
            return VERUS_V2;
        }
        else
        {
            return CURRENT_VERSION;
        }
    }
};

// this class is used to address the type mismatch that existed between nodes, where block headers
// were being serialized by senders as CBlock and deserialized as CBlockHeader + an assumed extra
// compact value. although it was working, I made this because it did break, and makes the connection
// between CBlock and CBlockHeader more brittle.
// by using this intentionally specified class instead, we remove an instability in the code that could break
// due to unrelated changes, but stay compatible with the old method.
class CNetworkBlockHeader : public CBlockHeader
{
    public:
        std::vector<CTransaction> compatVec;

    CNetworkBlockHeader() : CBlockHeader()
    {
        SetNull();
    }

    CNetworkBlockHeader(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(compatVec);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        compatVec.clear();    
    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vMerkleTree.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashFinalSaplingRoot   = hashFinalSaplingRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nSolution      = nSolution;
        return block;
    }

    // Build the in-memory merkle tree for this block and return the merkle root.
    // If non-NULL, *mutated is set to whether mutation was detected in the merkle
    // tree (a duplication of transactions in the block leading to an identical
    // merkle root).
    uint256 BuildMerkleTree(bool* mutated = NULL) const;

    std::vector<uint256> GetMerkleBranch(int nIndex) const;
    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);
    std::string ToString() const;
};


uint256 BuildMerkleTree(bool* fMutated, const std::vector<uint256> leaves,
        std::vector<uint256> &vMerkleTree);

std::vector<uint256> GetMerkleBranch(int nIndex, int nLeaves, const std::vector<uint256> &vMerkleTree);


/**
 * Custom serializer for CBlockHeader that omits the nonce and solution, for use
 * as input to Equihash.
 */
class CEquihashInput : private CBlockHeader
{
public:
    CEquihashInput(const CBlockHeader &header)
    {
        CBlockHeader::SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashFinalSaplingRoot);
        READWRITE(nTime);
        READWRITE(nBits);
    }
};


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }

    friend bool operator==(const CBlockLocator& a, const CBlockLocator& b) {
        return (a.vHave == b.vHave);
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
