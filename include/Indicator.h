#pragma once
// ============================================================
//  Indicator — Abstract Base Class (Abstraction)
//  Demonstrates: Abstract class, pure virtual functions,
//                encapsulation, operator overloading,
//                virtual destructor
// ============================================================
#include <string>
#include <iostream>
#include <memory>

class Indicator {
protected:
    int         id_;
    std::string value_;
    std::string severity_;      // Critical / High / Medium / Low
    std::string status_;        // Active / Inactive / Archived
    bool        is_malicious_;
    int         confidence_score_;
    std::string tags_;
    std::string context_;
    int         actor_id_;
    int         reported_by_;
    std::string first_seen_;
    std::string last_seen_;

public:
    // ── Constructor ──
    Indicator(const std::string& value,
              const std::string& severity  = "Medium",
              bool               malicious = true,
              int                confidence = 50);

    // ── Virtual destructor (must have for polymorphic base) ──
    virtual ~Indicator() = default;

    // ── Pure virtual functions — must override in derived classes ──
    virtual std::string getType()        const = 0;  // "IP", "Domain", "URL", "Hash"
    virtual double      analyze()        const = 0;  // Returns risk score 0–10
    virtual std::string getDescription() const = 0;
    virtual void        display()        const = 0;

    // ── Common virtual (can override) ──
    virtual std::string getSeverityLabel() const;

    // ── Getters ──
    int         getId()             const { return id_; }
    std::string getValue()          const { return value_; }
    std::string getSeverity()       const { return severity_; }
    std::string getStatus()         const { return status_; }
    bool        isMalicious()       const { return is_malicious_; }
    int         getConfidence()     const { return confidence_score_; }
    std::string getTags()           const { return tags_; }
    std::string getContext()        const { return context_; }
    int         getActorId()        const { return actor_id_; }
    int         getReportedBy()     const { return reported_by_; }
    std::string getFirstSeen()      const { return first_seen_; }
    std::string getLastSeen()       const { return last_seen_; }

    // ── Setters ──
    void setId(int id)                            { id_ = id; }
    void setSeverity(const std::string& s)        { severity_ = s; }
    void setStatus(const std::string& s)          { status_ = s; }
    void setMalicious(bool m)                     { is_malicious_ = m; }
    void setConfidence(int c)                     { confidence_score_ = c; }
    void setTags(const std::string& t)            { tags_ = t; }
    void setContext(const std::string& c)         { context_ = c; }
    void setActorId(int id)                       { actor_id_ = id; }
    void setReportedBy(int id)                    { reported_by_ = id; }
    void setFirstSeen(const std::string& ts)      { first_seen_ = ts; }
    void setLastSeen(const std::string& ts)       { last_seen_ = ts; }

    // ── Operator overloading ──
    bool operator< (const Indicator& other) const;  // Sort by confidence (descending)
    bool operator==(const Indicator& other) const;  // Same value and type

    // Friend function: stream output operator
    friend std::ostream& operator<<(std::ostream& os, const Indicator& ind);
};
