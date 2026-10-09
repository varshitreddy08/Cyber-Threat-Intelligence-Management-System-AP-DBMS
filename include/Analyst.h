#pragma once
// ============================================================
//  Analyst — Derived from User (Inheritance)
//  Demonstrates: Inheritance, vector of assigned tasks,
//                restricted access control
// ============================================================
#include "User.h"
#include <vector>

class Analyst : public User {
private:
    std::vector<int> assigned_incident_ids_;

public:
    Analyst(int id, const std::string& username,
            const std::string& email,
            const std::string& dept = "Threat Intelligence");

    void        displayInfo()                           const override;
    bool        canAccess(const std::string& resource)  const override;
    std::string getRoleDescription()                    const override;

    void assignIncident(int incident_id);
    void removeIncident(int incident_id);
    const std::vector<int>& getAssignedIncidents() const { return assigned_incident_ids_; }
    int  getWorkload() const { return static_cast<int>(assigned_incident_ids_.size()); }
};
