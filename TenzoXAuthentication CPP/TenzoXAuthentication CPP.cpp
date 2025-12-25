#include "TenzoXAuthentication.hpp"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    TXA::Auth txa("", "", "1.0");

    txa.Init();


    while (!txa.Initialized()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "TXA SDK Initialized!\n";


    std::string username, password;

    std::cout << "Enter username: ";
    std::cin >> username;

    std::cout << "Enter password: ";
    std::cin >> password;

    std::cout << "\nLogging in...\n";
    TXA::Auth::LoginResult loginResult = txa.Login(username, password);

    if (loginResult.Success) {
        std::cout << "\n=== LOGIN SUCCESSFUL ===\n";
        std::cout << "Welcome, " << loginResult.User.Username << "!\n";
        std::cout << "Subscription: " << loginResult.User.Subscription << "\n";
        std::cout << "Expiry: " << loginResult.User.Expiry << "\n";
        std::cout << "Message: " << loginResult.Message << "\n\n";

        if (txa.LoggedIn()) {
            std::cout << "User is logged in!\n";
        }
        if (txa.RefreshVariables()) {
            std::cout << "Variables refreshed successfully!\n";
            std::cout << "Response: " << txa.Response() << "\n\n";
        }
        else {
            std::cout << "Failed to refresh variables\n";
        }

        std::cout << "\n=== APPLICATION VARIABLES ===\n";
   
        std::cout << "Test Api: " << txa["testing_variable"] << "\n\n";


        std::cout << "Response: " << txa.Response() << "\n\n";
       
     
    }
    else {
        std::cout << "\n=== LOGIN FAILED ===\n";
        std::cout << "Error: " << loginResult.Message << "\n";
        std::cout << "TXA Response: " << txa.Response() << "\n";
    }



    std::cout << "\n=== REGISTRATION TEST ===\n";
    std::string regUser, regPass, licenseKey;

    std::cout << "Enter new username: ";
    std::cin >> regUser;

    std::cout << "Enter new password: ";
    std::cin >> regPass;

    std::cout << "Enter license key: ";
    std::cin >> licenseKey;

    TXA::Auth::RegisterResult regResult = txa.Register(regUser, regPass, licenseKey);

    if (regResult.Success) {
        std::cout << "Registration successful!\n";
        std::cout << "Message: " << regResult.Message << "\n";
    } else {
        std::cout << "Registration failed!\n";
        std::cout << "Error: " << regResult.Message << "\n";
    }

    std::cout << "\n=== APPLICATION STATUS ===\n";
    std::cout << "Initialized: " << (txa.Initialized() ? "Yes" : "No") << "\n";
    std::cout << "Logged In: " << (txa.LoggedIn() ? "Yes" : "No") << "\n";
    std::cout << "Active: " << (txa.Active() ? "Yes" : "No") << "\n";

    std::cout << "\nPress Enter to exit...";
    std::cin.ignore();
    std::cin.get();

    return 0;

}
