// Copyright (c) 2018 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_SOLUTIONDATA_H
#define BITCOIN_PRIMITIVES_SOLUTIONDATA_H

#include "serialize.h"
#include "uint256.h"
#include "arith_uint256.h"

enum SolutionConstants
{
    SOLUTION_POW = 1,        // if set, this is a PoW solution, otherwise, not
    SOLUTION_PBAAS_HEADER_SIZE = 4+32+32+32+4+32
};

class CActivationHeight
{
    public:
        static const int32_t MAX_HEIGHT = 0x7fffffff;
        static const int32_t DEFAULT_UPGRADE_HEIGHT = MAX_HEIGHT;
        static const int32_t NUM_VERSIONS = 3;
        static const int32_t SOLUTION_VERUSV2 = 1;
        static const int32_t SOLUTION_VERUSV3 = 2;
        bool active;
        int32_t heights[NUM_VERSIONS];
        CActivationHeight() : heights{0, DEFAULT_UPGRADE_HEIGHT, DEFAULT_UPGRADE_HEIGHT}, active(true) {}

        void SetActivationHeight(int32_t version, int32_t height)
        {
            assert(version < NUM_VERSIONS && version > 0);
            if (height < MAX_HEIGHT)
            {
                active = true;
            }
            heights[version] = height;
        }

        bool IsActivationHeight(int32_t version, int32_t height)
        {
            assert(version < NUM_VERSIONS && version > 0);
            return active && heights[version] == height;
        }

        int32_t ActiveVersion(int32_t height)
        {
            if (!active)
                return 0;

            int32_t ver = 0;
            for (int32_t i = 0; i < NUM_VERSIONS; i++)
            {
                if (heights[i] > height)
                {
                    break;
                }
                ver = i;
            }
            return ver;
        }
};

class CConstVerusSolutionVector
{
    public:
        static CActivationHeight activationHeight;
        static const bool SOLUTION_SIZE_FIXED = true;

        CConstVerusSolutionVector() {}

        static uint32_t GetVersionByHeight(uint32_t height)
        {
            return activationHeight.ActiveVersion(height);
        }

        static uint32_t Version(const std::vector<unsigned char> &vch)
        {
            if (activationHeight.ActiveVersion(0x7fffffff) > 0 && vch.size() >= 4)
            {
                return vch[0] + (vch[1] << 8) + (vch[2] << 16) + (vch[3] << 24);
            }
            else
            {
                return 0;
            }
        }

        static bool SetVersion(std::vector<unsigned char> &vch, uint32_t v)
        {
            if (activationHeight.active && vch.size() >= 4)
            {
                vch[0] = v & 0xff;
                vch[1] = (v >> 8) & 0xff;
                vch[2] = (v >> 16) & 0xff;
                vch[3] = (v >> 24) & 0xff;
                return true;
            }
            else
            {
                return false;
            }
        }

        static bool SetVersionByHeight(std::vector<unsigned char> &vch, uint32_t height)
        {
            return SetVersion(vch, activationHeight.ActiveVersion(height));
        }

        static uint32_t Descriptor(const std::vector<unsigned char> &vch)
        {
            if (Version(vch) >= CActivationHeight::SOLUTION_VERUSV3 && vch.size() >= 8)
            {
                return vch[4] + (vch[5] << 8) + (vch[6] << 16) + (vch[7] << 24);
            }
            else
            {
                return 0;
            }
        }

        static bool SetDescriptor(std::vector<unsigned char> &vch, uint32_t d)
        {
            if (Version(vch) >= CActivationHeight::SOLUTION_VERUSV3 && vch.size() >= 8)
            {
                vch[0] = d & 0xff;
                vch[1] = (d >> 8) & 0xff;
                vch[2] = (d >> 16) & 0xff;
                vch[3] = (d >> 24) & 0xff;
                return true;
            }
            else
            {
                return false;
            }
        }

        // returns 0 if not PBaaS, 1 if PBaaS PoW, -1 if PBaaS PoS
        static int32_t IsPBaaS(const std::vector<unsigned char> &vch)
        {
            if (Version(vch) == CActivationHeight::SOLUTION_VERUSV3)
            {
                return  (Descriptor(vch) & SOLUTION_POW) ? 1 : -1;
            }
            return 0;
        }
};

class CVerusSolutionVector
{
    private:
        static CConstVerusSolutionVector activationHeight;
        std::vector<unsigned char> &vch;

    public:
        static const bool SOLUTION_SIZE_FIXED = true;
        static const uint32_t HEADER_BASESIZE = 143;
        static const uint32_t SOLUTION_SIZE = 1344;
        static const uint32_t OVERHEAD_SIZE = 8;

        CVerusSolutionVector(std::vector<unsigned char> &_vch) : vch(_vch) { }

        static uint32_t GetVersionByHeight(uint32_t height)
        {
            return activationHeight.GetVersionByHeight(height);
        }

        uint32_t Version()
        {
            return activationHeight.Version(vch);
        }

        bool SetVersion(uint32_t v)
        {
            activationHeight.SetVersion(vch, v);
        }

        bool SetVersionByHeight(uint32_t height)
        {
            return activationHeight.SetVersionByHeight(vch, height);
        }

        uint32_t Descriptor()
        {
            return activationHeight.Descriptor(vch);
        }

        bool SetDescriptor(uint32_t d)
        {
            return activationHeight.SetDescriptor(vch, d);
        }

        // returns 0 if not PBaaS, 1 if PBaaS PoW, -1 if PBaaS PoS
        int32_t IsPBaaS()
        {
            return activationHeight.IsPBaaS(vch);
        }

        // return a vector of bytes that contains the internal data for this solution vector
        uint32_t ExtraDataLen()
        {
            int len;

            if (Version() < CActivationHeight::SOLUTION_VERUSV3)
            {
                len = 0;
            }
            else
            {
                // calculate number of bytes, minus the OVERHEAD_SIZE byte version and extra nonce at the end of the solution
                len = (vch.size() - ((HEADER_BASESIZE + vch.size()) % 32)) - OVERHEAD_SIZE;
            }

            return len < 0 ? 0 : (uint32_t)len;
        }

        uint32_t GetRequiredSolutionSize(uint32_t extraDataLen)
        {
            // round up to nearest 32 bytes
            return extraDataLen + OVERHEAD_SIZE + (32 - ((extraDataLen + OVERHEAD_SIZE + HEADER_BASESIZE) % 32));
        }

        void ResizeExtraData(uint32_t newSize)
        {
            vch.resize(GetRequiredSolutionSize(newSize));
        }

        // return a vector of bytes that contains the internal data for this solution vector
        unsigned char *ExtraDataPtr()
        {
            if (ExtraDataLen())
            {
                return &(vch.data()[OVERHEAD_SIZE]);
            }
            else
            {
                return NULL;
            }
        }

        // return a vector of bytes that contains the internal data for this solution vector
        void GetExtraData(std::vector<unsigned char> &dataVec)
        {
            int len = ExtraDataLen();

            if (len > 0)
            {
                dataVec.resize(len);
                std::memcpy(&(dataVec.data()[OVERHEAD_SIZE]), &(vch.data()[OVERHEAD_SIZE]), len);
            }
            else
            {
                dataVec.clear();
            }
        }

        // set the extra data with a pointer to bytes and length
        bool SetExtraData(const unsigned char *pbegin, uint32_t len)
        {
            if (Version() < CActivationHeight::SOLUTION_VERUSV3)
            {
                return false;
            }

            // calculate number of bytes, minus the 4 byte version and extra nonce at the end of the solution
            int l = (vch.size() - ((HEADER_BASESIZE + vch.size()) % 32)) - OVERHEAD_SIZE;
            if (len > l)
            {
                return false;
            }
            else
            {
                std::memcpy(&(vch.data()[4]), pbegin, len);
                return true;
            }
        }
};

#endif // BITCOIN_PRIMITIVES_SOLUTIONDATA_H
