// file_info.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <list>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <windows.h>
#include <wincrypt.h>
#include <sstream>

// Struct definition
struct file_info {
    std::string file_name;
    std::string file_path;
    std::string md5;
    std::string hash_sha1;
    std::string sha256;
    std::string time_created_file;
    std::string time_modified_file;
};

// Function to compute hash (MD5, SHA1, SHA256)
std::string compute_hash(const std::string& file_path, ALG_ID alg_id, DWORD hash_len) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string hash_string;

    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, alg_id, 0, 0, &hHash)) {
            std::ifstream file(file_path, std::ios::binary);
            if (file) {
                char buffer[4096];
                while (file.read(buffer, sizeof(buffer))) {
                    CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer), file.gcount(), 0);
                }
                CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer), file.gcount(), 0);

                BYTE hash[64];
                DWORD hash_size = hash_len;
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_size, 0)) {
                    std::ostringstream oss;
                    for (DWORD i = 0; i < hash_size; ++i) {
                        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                    }
                    hash_string = oss.str();
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }

    return hash_string;
}

void compute_hash_async(const std::string& file_path, ALG_ID alg_id, DWORD hash_len, std::string& hash_result) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, alg_id, 0, 0, &hHash)) {
            std::ifstream file(file_path, std::ios::binary);
            if (file) {
                char buffer[4096];
                while (file.read(buffer, sizeof(buffer))) {
                    CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer), file.gcount(), 0);
                }
                CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer), file.gcount(), 0);

                BYTE hash[64];
                DWORD hash_size = hash_len;
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_size, 0)) {
                    std::ostringstream hex_stream;
                    for (DWORD i = 0; i < hash_size; ++i) {
                        hex_stream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                    }
                    hash_result = hex_stream.str();
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
}

// Function to compute MD5 hash
std::string compute_md5(const std::string& file_path) {
    return compute_hash(file_path, CALG_MD5, 16);
}

// Function to compute SHA1 hash
std::string compute_sha1(const std::string& file_path) {
    return compute_hash(file_path, CALG_SHA1, 20);
}

// Function to compute SHA256 hash
std::string compute_sha256(const std::string& file_path) {
    return compute_hash(file_path, CALG_SHA_256, 32);
}

std::string format_time(const SYSTEMTIME& st) {
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(4) << st.wYear << "-" << std::setw(2) << st.wMonth << "-" << std::setw(2) << st.wDay
        << " " << std::setw(2) << st.wHour << ":" << std::setw(2) << st.wMinute << ":" << std::setw(2) << st.wSecond;
    return oss.str();
}

// Function to list file information
std::list<file_info> list_file_info(const std::string& directory, bool recursive) {
    std::list<file_info> files_list;

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((directory + "\\*.*").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // Skip "." and ".." directories
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0 && recursive) {
                    std::string subdirectory = directory + "\\" + findData.cFileName;
                    auto subfiles = list_file_info(subdirectory, recursive);
                    files_list.insert(files_list.end(), subfiles.begin(), subfiles.end());
                }
            }
            else {
                file_info fi;
                fi.file_name = findData.cFileName;
                fi.file_path = directory + "\\" + fi.file_name;
                fi.md5 = compute_md5(fi.file_path);
                Sleep(100);
                fi.hash_sha1 = compute_sha1(fi.file_path);
                Sleep(100);
                fi.sha256 = compute_sha256(fi.file_path);
                Sleep(100);

                SYSTEMTIME stCreate, stModified;
                FileTimeToSystemTime(&findData.ftCreationTime, &stCreate);
                FileTimeToSystemTime(&findData.ftLastWriteTime, &stModified);
                fi.time_created_file = format_time(stCreate);
                fi.time_modified_file = format_time(stModified);

                /*SYSTEMTIME stCreate, stModified;
                FileTimeToSystemTime(&findData.ftCreationTime, &stCreate);
                FileTimeToSystemTime(&findData.ftLastWriteTime, &stModified);
                char buffer[256];
                GetDateFormatA(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &stCreate, NULL, buffer, sizeof(buffer));
                std::string dateStr(buffer);
                GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &stCreate, NULL, buffer, sizeof(buffer));
                std::string timeStr(buffer);
                fi.time_created_file = dateStr + " " + timeStr;

                GetDateFormatA(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &stModified, NULL, buffer, sizeof(buffer));
                dateStr = buffer;
                GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &stModified, NULL, buffer, sizeof(buffer));
                timeStr = buffer;
                fi.time_modified_file = dateStr + " " + timeStr;*/

                files_list.push_back(fi);
            }
        } while (FindNextFileA(hFind, &findData) != 0);
        FindClose(hFind);
    }

    return files_list;
}


int main(int argc, char** argv) {
    std::string directory = std::string(argv[1]);
    printf("directory: %s\n", directory.c_str());
    bool recursive = true;

    std::list<file_info> files = list_file_info(directory, true);
    for (const auto& fi : files) {
        std::cout << "File Name: " << fi.file_name << "\n";
        std::cout << "File Path: " << fi.file_path << "\n";
        std::cout << "MD5: " << fi.md5 << "\n";
        std::cout << "SHA1: " << fi.hash_sha1 << "\n";
        std::cout << "SHA256: " << fi.sha256 << "\n";
        std::cout << "Time Created: " << fi.time_created_file << "\n";
        std::cout << "Time Modified: " << fi.time_modified_file << "\n";
        std::cout << "-----------------------------------\n";
    }

    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
