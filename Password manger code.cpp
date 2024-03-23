#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <ctime>
#include <openssl/md5.h> // MD5 hashing
#include <unordered_map>

// Structure to hold username and password
struct Credential {
    std::string username;
    std::string password;

    Credential(const std::string& uname, const std::string& pwd) : username(uname), password(pwd) {}
};

// Caesar cipher encryption function
std::string encrypt(const std::string& text, int shift) {
    std::string result = "";

    for (char ch : text) {
        if (isalpha(ch)) {
            char shifted = (isupper(ch)) ? 'A' + (ch - 'A' + shift) % 26 : 'a' + (ch - 'a' + shift) % 26;
            result += shifted;
        } else {
            result += ch;
        }
    }

    return result;
}

// Caesar cipher decryption function
std::string decrypt(const std::string& text, int shift) {
    return encrypt(text, 26 - shift); // Decrypt by shifting in opposite direction
}

class PasswordManager {
private:
    std::unordered_map<std::string, std::vector<Credential>> userCredentials;

public:
    // Function to save new username and password for the currently logged-in user
    void saveCredential(const std::string& loggedInUser, const std::string& username, const std::string& password) {
        std::string encryptedPassword = encrypt(password, 3); // Shift by 3 positions

        auto it = userCredentials.find(loggedInUser);
        if (it != userCredentials.end()) {
            it->second.emplace_back(username, encryptedPassword);
        } else {
            userCredentials.emplace(loggedInUser, std::vector<Credential>{{username, encryptedPassword}});
        }
        std::cout << "Your username and password is saved successfully!" << std::endl;
    }

    // Function to retrieve saved credentials for the currently logged-in user
    void retrieveCredentials(const std::string& loggedInUser) {
        auto it = userCredentials.find(loggedInUser);
        if (it != userCredentials.end()) {
            std::cout << "User's credentials have been stored" << loggedInUser << "':" << std::endl;
            for (const auto& cred : it->second) {
                std::cout << "Username:" << cred.username << ", Password:" << decrypt(cred.password, 3) << std::endl; // Decrypt password before displaying
            }
        } else {
            std::cout << "User credentials not found" << loggedInUser << "'" << std::endl;
        }
    }
};

// MD5 hashing function (now public)
std::string hashPassword(const std::string& password) {
    MD5_CTX mdContext;
    MD5_Init(&mdContext);
    MD5_Update(&mdContext, password.c_str(), password.size());

    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_Final(digest, &mdContext);

    char mdString[33];
    for(int i = 0; i < 16; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
    
    return std::string(mdString);
}

// Function to generate a random password
std::string generateRandomPassword(int length) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    std::string password;
    srand(time(0)); // Seed for random number generation
    for (int i = 0; i < length; ++i) {
        password += charset[rand() % charset.length()];
    }
    return password;
}

class UserManager {
private:
    std::unordered_map<std::string, std::string> users; // Store usernames and hashed passwords

public:
    // Function to register a new user
    void registerUser(const std::string& username, const std::string& password) {
        std::string hashedPassword = hashPassword(password);
        users.emplace(username, hashedPassword);
        std::cout << "User registration completed" << std::endl;
    }

    // Function to authenticate user
    bool authenticate(const std::string& username, const std::string& password) {
        std::string hashedPassword = hashPassword(password);

        auto it = users.find(username);
        if (it != users.end() && it->second == hashedPassword) {
            return true;
        }
        return false;
    }
};

int main() {
    UserManager userManager;
    PasswordManager passwordManager;
    std::string loggedInUser;

    std::cout << "Hello! You've entered the Password Manager." << std::endl;

    while (true) {
        std::cout << "\nMenu:" << std::endl;
        std::cout << "1. Create an account" << std::endl;
        std::cout << "2. Sign in" << std::endl;
        std::cout << "3. Shutdown" << std::endl;
        std::cout << "Choose a menu item:";

        int choice;
        std::cin >> choice;
        std::cin.ignore(); // Clear input buffer

        switch (choice) {
            case 1: {
                std::string username, password;
                std::cout << "Choose a username:";
                std::getline(std::cin, username);
                std::cout << "Create a password:";
                std::getline(std::cin, password);
                userManager.registerUser(username, password);
                break;
            }
            case 2: {
                std::string username, password;
                std::cout << "Choose a username:";
                std::getline(std::cin, username);
                std::cout << "Create a password:";
                std::getline(std::cin, password);
                if (userManager.authenticate(username, password)) {
                    loggedInUser = username;
                    std::cout << "You're logged in!" << std::endl;
                    while (true) {
                        std::cout << "\nMenu options:" << std::endl;
                        std::cout << "1. Save new account information" << std::endl;
                        std::cout << "2. View saved username and password" << std::endl;
                        std::cout << "3. Get a randomly generated password" << std::endl;
                        std::cout << "4. Sign out" << std::endl;
                        std::cout << "Select a menu option: ";
                        std::cin >> choice;
                        std::cin.ignore(); // Clear input buffer
                        switch (choice) {
                            case 1: {
                                std::string newUsername, newPassword;
                                std::cout << "Choose a username: ";
                                std::getline(std::cin, newUsername);
                                std::cout << "Create a password: ";
                                std::getline(std::cin, newPassword);
                                passwordManager.saveCredential(loggedInUser, newUsername, newPassword);
                                break;
                            }
                            case 2: {
                                passwordManager.retrieveCredentials(loggedInUser);
                                break;
                            }
                            case 3: {
                                int passwordLength;
                                std::cout << "Enter the desired password length: ";
                                std::cin >> passwordLength;
                               
                                std::cin.ignore(); // Clear input buffer
                                std::string newPassword = generateRandomPassword(passwordLength);
                                std::cout << "Password Generated: " << newPassword << std::endl;
                                break;
                            }
                            case 4: {
                                std::cout << "You have been logged out." << std::endl;
                                loggedInUser = "";
                                goto logout;
                            }
                            default:
                                std::cout << "Oops! That's not a valid option. Please choose again." << std::endl;
                                break;
                        }
                    }
                } else {
                    std::cout << "Authentication unsuccessful. Please check your username and password." << std::endl;
                }
                break;
            }
            case 3: {
                std::cout << "Goodbye!" << std::endl;
                return 0;
            }
            default:
                std::cout << "Oops! That's not a valid option. Please choose again." << std::endl;
        }
    logout:;
    }
    return 0;
}