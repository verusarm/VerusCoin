/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS cross chain communication.
 * 
 * In merge mining and notarization, Verus acts as a hub that other PBaaS chains
 * call via RPC in order to get information that allows earning and submitting
 * notarizations.
 * 
 */

#ifndef CROSSCHAINRPC_H
#define CROSSCHAINRPC_H

#include <univalue.h>

static const int DEFAULT_RPC_TIMEOUT=900;

class CrossChainRPCData
{
public:
    std::string host;
    int32_t port;
    std::string credentials;

    CrossChainRPCData() : port(0) {}

    CrossChainRPCData(std::string Host, int32_t Port, std::string Credentials) :
        host(Host), port(Port), credentials(Credentials) {}
    
    static CrossChainRPCData LoadFromConfig(std::string fPath="");

    inline static uint160 GetChainID(std::string name)
    {
        const char *chainName = name.c_str();
        uint256 chainHash = Hash(chainName, chainName + strlen(chainName));
        return Hash160(chainHash.begin(), chainHash.end());
    }

    inline static uint160 GetConditionID(uint160 &cid, int32_t condition)
    {
        const char *condStr = itostr(condition).c_str();
        uint256 chainHash = Hash(condStr, condStr + strlen(condStr), (char *)&cid, ((char *)&cid) + sizeof(cid));
        return Hash160(chainHash.begin(), chainHash.end());
    }
    inline static uint160 GetConditionID(std::string name, int32_t condition)
    {
        uint160 cid = GetChainID(name);
        const char *condStr = itostr(condition).c_str();
        uint256 chainHash = Hash(condStr, condStr + strlen(condStr), (char *)&cid, ((char *)&cid) + sizeof(cid));
        return Hash160(chainHash.begin(), chainHash.end());
    }
};

// credentials for now are "user:password"
UniValue RPCCall(const std::string& strMethod, 
                 const UniValue& params, 
                 const std::string credentials="user:pass", 
                 int port=27486, 
                 const std::string host="127.0.0.1", 
                 int timeout=DEFAULT_RPC_TIMEOUT);

#endif
