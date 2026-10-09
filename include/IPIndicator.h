#pragma once
// ============================================================
//  IPIndicator — Derived from Indicator (Inheritance)
//  Demonstrates: Single inheritance, method overriding,
//                derived class constructors
// ============================================================
#include "Indicator.h"

class IPIndicator : public Indicator {
private:
    std::string ip_version_;       // IPv4 or IPv6
    std::string geolocation_;
    int         reputation_score_; // 0=malicious, 100=clean

public:
    IPIndicator(const std::string& ip,
                const std::string& severity    = "Medium",
                bool               malicious   = true,
                int                confidence  = 50,
                const std::string& ip_version  = "IPv4",
                const std::string& geo         = "",
                int                reputation  = 50);

    // ── Override pure virtual functions (Polymorphism) ──
    std::string getType()        const override { return "IP"; }
    double      analyze()        const override;
    std::string getDescription() const override;
    void        display()        const override;

    // ── IP-specific getters/setters ──
    std::string getIPVersion()      const { return ip_version_; }
    std::string getGeolocation()    const { return geolocation_; }
    int         getReputation()     const { return reputation_score_; }
    void        setGeolocation(const std::string& geo) { geolocation_ = geo; }
    void        setReputation(int r)                   { reputation_score_ = r; }

    // ── IP-specific analysis ──
    bool isPrivateAddress() const;
    bool isLoopback()       const;
};
