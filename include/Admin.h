#pragma once
// ============================================================
//  Admin — Derived from User (Inheritance)
//  Demonstrates: Single inheritance, static member variables,
//                static methods, full access control
// ============================================================
#include "User.h"

class Admin : public User {
private:
    static int admin_count_;    // Static member: shared across all Admin objects
    std::string access_level_;  // "super" or "standard"

public:
    Admin(int id, const std::string& username,
          const std::string& email,
          const std::string& access_level = "standard",
          const std::string& dept = "Administration");

    ~Admin() override;   // Decrements admin_count_

    // ── Override pure virtual functions ──
    void        displayInfo()                           const override;
    bool        canAccess(const std::string& resource)  const override;
    std::string getRoleDescription()                    const override;

    // ── Admin-specific operations ──
    void manageUsers()    const;
    void viewAuditLog()   const;
    void generateReport() const;

    // ── Static method ──
    static int  getAdminCount() { return admin_count_; }
    std::string getAccessLevel() const { return access_level_; }
};
