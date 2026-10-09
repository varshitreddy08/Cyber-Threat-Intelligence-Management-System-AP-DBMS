#pragma once
// ============================================================
//  ThreatActor — Entity class
//  Demonstrates: Encapsulation, operator overloading,
//                shared_ptr usage, copy constructor
// ============================================================
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include "Indicator.h"

class ThreatActor {
private:
    int         actor_id_;
    std::string name_;
    std::string type_;            // APT, Cybercriminal, Hacktivist, etc.
    std::string origin_country_;
    std::string motivation_;
    int         sophistication_;  // 1–10
    std::string aliases_;
    std::string first_seen_;
    std::string last_seen_;
    std::string description_;
    bool        is_active_;

    // Associated indicators (uses polymorphism — stores any Indicator subtype)
    std::vector<std::shared_ptr<Indicator>> indicators_;

public:
    ThreatActor(const std::string& name,
                const std::string& type,
                const std::string& country = "",
                const std::string& motivation = "",
                int                sophistication = 5);

    // ── Copy constructor (deep copy of indicators) ──
    ThreatActor(const ThreatActor& other);

    // ── Getters ──
    int         getId()               const { return actor_id_; }
    std::string getName()             const { return name_; }
    std::string getType()             const { return type_; }
    std::string getCountry()          const { return origin_country_; }
    std::string getMotivation()       const { return motivation_; }
    int         getSophistication()   const { return sophistication_; }
    std::string getDescription()      const { return description_; }
    bool        isActive()            const { return is_active_; }
    int         getIndicatorCount()   const { return static_cast<int>(indicators_.size()); }

    // ── Setters ──
    void setId(int id)                             { actor_id_ = id; }
    void setDescription(const std::string& d)      { description_ = d; }
    void setActive(bool a)                         { is_active_ = a; }
    void setAliases(const std::string& a)          { aliases_ = a; }
    void setFirstSeen(const std::string& d)        { first_seen_ = d; }
    void setLastSeen(const std::string& d)         { last_seen_ = d; }

    // ── Indicator management (polymorphic) ──
    void addIndicator(std::shared_ptr<Indicator> ind);
    void displayIndicators() const;

    // ── Display ──
    void display() const;

    // ── Operator overloading ──
    bool operator< (const ThreatActor& other) const;  // Sort by sophistication
    bool operator==(const ThreatActor& other) const;

    friend std::ostream& operator<<(std::ostream& os, const ThreatActor& ta);
};
