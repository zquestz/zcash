// Copyright (c) 2020 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "tze.h"
#include "librustzcash.h"

/**
 * Singleton implementation of librustzcash-backed TZE
 */
class LibrustzcashTZE : public TZE {
public:
    static LibrustzcashTZE& getInstance()
    {
        static LibrustzcashTZE instance;
        return instance;
    }

    virtual bool check(const CTzeData& predicate, const CTzeData& witness, const TzeContext& ctx) const {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << ctx.tx;

        // TODO: serialize ctx.tx into txser
        return librustzcash_tze_verify(
            predicate.extensionId,
            predicate.mode,
            predicate.payload.data(),
            witness.extensionId,
            witness.mode,
            witness.payload.data(),
            ctx.height,
            (unsigned char*)&ss[0]
        );
    }

    // disable copy-constructor and assignment
    LibrustzcashTZE(LibrustzcashTZE const&) = delete;
    void operator=(LibrustzcashTZE const&)  = delete;
private:
    LibrustzcashTZE() {}
};
