#pragma once
// ============================================================
//  DomainIndicator — Derived from Indicator (Inheritance)
// ============================================================
#include "Indicator.h"

class DomainIndicator : public Indicator {
private:
    std::string registrar_;
    bool        is_dga_;       // Domain Generation Algorithm — suspicious
    int         domain_age_days_;

public:
    DomainIndicator(const std::string& domain,
                    const std::string& severity   = "Medium",
                    bool               malicious  = true,
                    int                confidence = 50,
                    const std::string& registrar  = "",
                    bool               is_dga     = false,
                    int                age_days   = 0);

    std::string getType()        const override { return "Domain"; }
    double      analyze()        const override;
    std::string getDescription() const override;
    void        display()        const override;

    std::string getRegistrar()   const { return registrar_; }
    bool        isDGA()          const { return is_dga_; }
    int         getDomainAge()   const { return domain_age_days_; }
    void        setDGA(bool b)         { is_dga_ = b; }
};
