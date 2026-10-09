#pragma once
// ============================================================
//  User — Abstract Base Class (Abstraction + Encapsulation)
//  Demonstrates: Abstract class, pure virtual, protected members,
//                virtual functions for polymorphic behavior
// ============================================================
#include <string>
#include <iostream>

class User {
protected:
    int         user_id_;
    std::string username_;
    std::string email_;
    std::string role_;
    std::string department_;
    bool        is_active_;
    std::string created_at_;
    std::string last_login_;

public:
    User(int id, const std::string& username,
         const std::string& email, const std::string& role,
         const std::string& dept = "");

    virtual ~User() = default;

    // ── Pure virtual — each role implements differently ──
    virtual void displayInfo()                             const = 0;
    virtual bool canAccess(const std::string& resource)   const = 0;
    virtual std::string getRoleDescription()               const = 0;

    // ── Common virtual ──
    virtual void login(const std::string& timestamp);

    // ── Getters ──
    int         getUserId()     const { return user_id_; }
    std::string getUsername()   const { return username_; }
    std::string getEmail()      const { return email_; }
    std::string getRole()       const { return role_; }
    std::string getDepartment() const { return department_; }
    bool        isActive()      const { return is_active_; }
    std::string getLastLogin()  const { return last_login_; }

    // ── Setters ──
    void setActive(bool a)                  { is_active_ = a; }
    void setLastLogin(const std::string& t) { last_login_ = t; }

    // ── Operator overloading ──
    bool operator==(const User& other) const;
    friend std::ostream& operator<<(std::ostream& os, const User& u);
};
