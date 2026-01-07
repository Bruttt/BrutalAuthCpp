#include <iostream>
#include "BrutalAuth.hpp"

int main() {
    BrutalAuth auth("application_id", "api.brutalauth.site", "1.2");

    std::cout << "=== BRUTAL AUTH CLIENT ===\n"
        << "1. Register new account\n"
        << "2. Login to existing account\n"
        << "Choose option (1 or 2): ";

    int choice = 0;
    if (!(std::cin >> choice)) return 0;

    if (choice == 1) {
        std::string license, username, password;
        std::cout << "Enter license key: ";
        std::cin >> license;
        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter password: ";
        std::cin >> password;

        if (auth.registerUser(license, username, password)) {
            std::cout << "Registration completed! You can now login.\n";
        }
        else {
        }
    }
    else if (choice == 2) {
        std::string username, password;
        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter password: ";
        std::cin >> password;

        if (auth.loginUser(username, password)) {
            std::cout << "Welcome! Application starting...\n";
            std::cout << "Press Enter to exit...\n";
            std::cin.ignore(1000000, '\n');
            std::cin.get();
        }
        else {
        }
    }
    return 0;
}
