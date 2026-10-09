#pragma once
// ============================================================
//  HashIndicator — Derived from Indicator (Inheritance)
// ============================================================
#include "Indicator.h"

class HashIndicator : public Indicator {
private:
    std::string hash_type_;    // MD5, SHA1, SHA256, SHA512
    std::string file_name_;
    long long   file_size_bytes_;

public:
    HashIndicator(const std::string& hash,
                  const std::string& severity    = "Medium",
                  bool               malicious   = true,
                  int                confidence  = 50,
                  const std::string& hash_type   = "SHA256",
                  const std::string& file_name   = "",
                  long long          file_size   = 0);

    std::string getType()        const override { return "Hash"; }
    double      analyze()        const override;
    std::string getDescription() const override;
    void        display()        const override;

    std::string getHashType()    const { return hash_type_; }
    std::string getFileName()    const { return file_name_; }
    long long   getFileSize()    const { return file_size_bytes_; }

    bool        isMD5()          const { return hash_type_ == "MD5"; }
    bool        isSHA256()       const { return hash_type_ == "SHA256"; }
    bool        validateLength() const;   // Check hash length vs type
};
