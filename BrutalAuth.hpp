#pragma once

#include <string>

class BrutalAuth {
public:
    /**
     * @param applicationId Your Application ID from the Dashboard
     * @param host Your Supabase host (e.g. "yourid.supabase.co")
     * @param version Your current App Version (e.g. "1.0.0")
     */
    BrutalAuth(std::string applicationId, std::string host, std::string version);

    /**
     * Registers a new user with a license key
     */
    bool registerUser(const std::string& licenseKey,
        const std::string& username,
        const std::string& password);

    /**
     * Logs in an existing user
     */
    bool loginUser(const std::string& username,
        const std::string& password);

private:
    std::string applicationId_;
    std::string host_;
    std::string version_; // Added this to match .cpp

    bool contains_success_true(const std::string& body);

    bool postJson(const std::string& pathOrUrl,
        const std::string& body,
        std::string& out);

    std::string makeJsonRegister(const std::string& licenseKey,
        const std::string& username,
        const std::string& password,
        const std::string& hwid,
        const std::string& applicationId);

    // Updated to include version parameter
    std::string makeJsonLogin(const std::string& username,
        const std::string& password,
        const std::string& hwid,
        const std::string& applicationId,
        const std::string& version);
};
