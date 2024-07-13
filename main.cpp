#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void log_error(const std::string& message) {
    std::cerr << "Error: " << message << std::endl;
}

double get_cpu_usage(HANDLE process, double interval = 0.5) {
    try {
        FILETIME ftime, fsys, fuser;
        ULARGE_INTEGER now, sys, user;
        double percent;

        GetSystemTimeAsFileTime(&ftime);
        memcpy(&now, &ftime, sizeof(FILETIME));

        if (!GetProcessTimes(process, &ftime, &ftime, &fsys, &fuser)) {
            throw std::runtime_error("Failed to get process times");
        }
        memcpy(&sys, &fsys, sizeof(FILETIME));
        memcpy(&user, &fuser, sizeof(FILETIME));

        std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(interval * 1000)));

        FILETIME ftime2, fsys2, fuser2;
        ULARGE_INTEGER now2, sys2, user2;

        GetSystemTimeAsFileTime(&ftime2);
        memcpy(&now2, &ftime2, sizeof(FILETIME));

        if (!GetProcessTimes(process, &ftime2, &ftime2, &fsys2, &fuser2)) {
            throw std::runtime_error("Failed to get process times");
        }
        memcpy(&sys2, &fsys2, sizeof(FILETIME));
        memcpy(&user2, &fuser2, sizeof(FILETIME));

        percent = (sys2.QuadPart - sys.QuadPart) + (user2.QuadPart - user.QuadPart);
        percent /= (now2.QuadPart - now.QuadPart);
        percent /= GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);

        return percent * 100;
    }
    catch (const std::exception& e) {
        log_error(std::string("Error in get_cpu_usage: ") + e.what());
        return -1;
    }
}

void monitor_process(DWORD pid, double cpu_threshold, double ram_threshold) {
    try {
        std::cout << "Attempting to monitor process with PID: " << pid << std::endl;

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (process == NULL) {
            throw std::runtime_error("Unable to open process");
        }

        PROCESS_MEMORY_COUNTERS_EX pmc;
        TCHAR process_name[MAX_PATH] = TEXT("<unknown>");

        for (int i = 0; i < 10; ++i) {  // Monitor for 10 iterations only
            double cpu_usage = get_cpu_usage(process);
            if (cpu_usage < 0) {
                throw std::runtime_error("Failed to get CPU usage");
            }

            if (!GetProcessMemoryInfo(process, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                throw std::runtime_error("Failed to get process memory info");
            }
            double ram_usage = pmc.WorkingSetSize / (1024.0 * 1024.0);  // Convert to MB

            if (!GetModuleBaseName(process, NULL, process_name, MAX_PATH)) {
                throw std::runtime_error("Failed to get process name");
            }

            std::cout << "Process Name: " << process_name << " | Process ID: " << pid
                << " | CPU Usage: " << cpu_usage << "% | RAM Usage: " << ram_usage << " MB" << std::endl;

            if (cpu_usage > cpu_threshold) {
                std::cout << "High CPU usage detected for process " << pid << "! Taking action..." << std::endl;
                break;
            }

            if (ram_usage > ram_threshold) {
                std::cout << "High RAM usage detected for process " << pid << "! Taking action..." << std::endl;
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        CloseHandle(process);
    }
    catch (const std::exception& e) {
        log_error(std::string("Error in monitor_process: ") + e.what());
    }
}

std::vector<DWORD> find_processes_by_path(const std::wstring& path) {
    std::vector<DWORD> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (process != NULL) {
                WCHAR exe_path[MAX_PATH];
                if (GetModuleFileNameExW(process, NULL, exe_path, MAX_PATH)) {
                    if (_wcsicmp(exe_path, path.c_str()) == 0) {
                        processes.push_back(pe32.th32ProcessID);
                    }
                }
                CloseHandle(process);
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return processes;
}

std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::wstring normalize_path(const std::wstring& path) {
    std::wstring normalized = path;
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    return normalized;
}

std::wstring get_filename_from_path(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? path : path.substr(pos + 1);
}

std::vector<DWORD> find_processes_by_name(const std::wstring& target_name) {
    std::vector<DWORD> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            std::wstring process_name = pe32.szExeFile;
            if (_wcsicmp(process_name.c_str(), target_name.c_str()) == 0) {
                processes.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return processes;
}

int main() {
    try {
        std::cout << "Process Monitor starting..." << std::endl;

        // Read configuration from JSON file
        std::ifstream config_file("config.json");
        if (!config_file.is_open()) {
            throw std::runtime_error("Unable to open config.json");
        }

        json config;
        config_file >> config;

        // Validate JSON structure
        if (!config.contains("exe_paths_to_monitor")) {
            throw std::runtime_error("Missing 'exe_paths_to_monitor' in config.json");
        }
        if (!config.contains("cpu_threshold")) {
            throw std::runtime_error("Missing 'cpu_threshold' in config.json");
        }
        if (!config.contains("ram_threshold")) {
            throw std::runtime_error("Missing 'ram_threshold' in config.json");
        }

        std::vector<std::wstring> exe_paths_to_monitor;
        for (const auto& path : config["exe_paths_to_monitor"]) {
            if (!path.is_string()) {
                throw std::runtime_error("Each path in 'exe_paths_to_monitor' must be a string");
            }
            exe_paths_to_monitor.push_back(utf8_to_wstring(path.get<std::string>()));
        }

        double cpu_threshold = config["cpu_threshold"].get<double>();
        double ram_threshold = config["ram_threshold"].get<double>();

        for (const auto& exe_path : exe_paths_to_monitor) {
            std::wstring normalized_path = normalize_path(exe_path);
            std::wstring target_name = get_filename_from_path(normalized_path);

            std::wcout << L"Monitoring process: " << target_name << std::endl;

            auto processes = find_processes_by_name(target_name);
            if (!processes.empty()) {
                for (DWORD pid : processes) {
                    monitor_process(pid, cpu_threshold, ram_threshold);
                }
            }
            else {
                std::wcout << L"No running process found with the name " << target_name << std::endl;
            }
        }

        std::cout << "Process Monitor finished." << std::endl;

        std::cout << "Process Monitor finished." << std::endl;
    }
    catch (const json::exception& e) {
        std::cerr << "JSON error: " << e.what() << std::endl;
        std::cerr << "Exception id: " << e.id << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown error occurred" << std::endl;
    }

    // Keep console window open
    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}