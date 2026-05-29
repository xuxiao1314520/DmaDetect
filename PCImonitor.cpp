#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <cstring>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdio.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

// ==================== FAULT_EVENT 结构体定义 ====================
typedef struct _FAULT_EVENT {
    ULONGLONG FaultAddress;
    USHORT    SourceId;
    UCHAR     Bus;
    UCHAR     Device;
    UCHAR     Function;
    UCHAR     FaultReason;
    UCHAR     AccessType;
    USHORT    PciVendorId;
    USHORT    PciDeviceId;
    UCHAR     PciClassCode;
    UCHAR     PciSubClass;
    CHAR      DeviceDesc[128];
    LARGE_INTEGER Timestamp;
} FAULT_EVENT, * PFAULT_EVENT;

// ==================== VT-d 驱动 IOCTL 定义 ====================
#define IOCTL_GET_FAULT_EVENT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_FAULT_COUNT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_VTD_INFO     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_VTD_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_DEBUG_OUTPUT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x920, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ==================== VTD_INFO 结构体定义 ====================
#pragma pack(push, 1)
typedef struct _VTD_INFO {
    UCHAR        VtdAccessible;
    UCHAR        Reserved0[3];
    ULONG        Version;
    ULONGLONG    Capability;
    ULONG        FaultRegOffset;
    ULONG        NumFaultRegs;
    ULONGLONG    PhysBase;
    ULONGLONG    FeatureControlMsr;
    UCHAR        VtXEnabled;
    UCHAR        VtDEnabled;
    UCHAR        Reserved1[2];
    CHAR         StatusMessage[256];
} VTD_INFO;
#pragma pack(pop)

// ==================== 设备状态枚举 ====================
enum DeviceProblemCode {
    PROBLEM_NONE = 0,
    PROBLEM_CM_FAILED = 1,
    PROBLEM_DISABLED = 22,
    PROBLEM_DRIVER_FAILED = 28,
    PROBLEM_DRIVER_LOAD_FAILED = 31,
    PROBLEM_DEVICE_REMOVED = 24,
    PROBLEM_START_FAILED = 10,
    PROBLEM_RESOURCE_CONFLICT = 12,
};

// ==================== 设备信息结构 ====================
struct DeviceInfo {
    std::string instanceId;
    std::string description;
    std::string hardwareId;
    WORD vendorId;
    WORD deviceId;
    WORD subsystemVendorId;
    WORD subsystemId;
    BYTE revisionId;
    BYTE baseClass;
    BYTE subClass;
    DWORD bar[6];
    WORD command;
    WORD busNumber;
    WORD deviceNumber;
    WORD functionNumber;
    bool present;
    FILETIME lastSeen;
    ULONG problemCode;
    std::string problemString;
    bool hasDriver;

    DeviceInfo() : vendorId(0), deviceId(0), subsystemVendorId(0), subsystemId(0),
        revisionId(0), baseClass(0), subClass(0), command(0),
        busNumber(0), deviceNumber(0), functionNumber(0),
        present(false), problemCode(0), hasDriver(false) {
        memset(bar, 0, sizeof(bar));
        memset(&lastSeen, 0, sizeof(lastSeen));
    }
};

// ==================== 辅助函数 ====================
std::string GetCurrentTimeString() {
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    std::ostringstream oss;
    oss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// ==================== Realtek DMA 检测器类 ====================
class RealtekDMADetector {
private:
    std::vector<DeviceInfo> m_attackHistory;
    std::set<WORD> m_realtekNICIds;

public:
    RealtekDMADetector() {
        InitializeRealtekNICIds();
    }

    void InitializeRealtekNICIds() {
        m_realtekNICIds.insert(0x8168);
        m_realtekNICIds.insert(0x8169);
        m_realtekNICIds.insert(0x8129);
        m_realtekNICIds.insert(0x8136);
        m_realtekNICIds.insert(0x8137);
        m_realtekNICIds.insert(0x8138);
        m_realtekNICIds.insert(0x8161);
        m_realtekNICIds.insert(0x8162);
        m_realtekNICIds.insert(0x8167);
        m_realtekNICIds.insert(0x8170);
        m_realtekNICIds.insert(0x8171);
        m_realtekNICIds.insert(0x8172);
        m_realtekNICIds.insert(0x8101);
        m_realtekNICIds.insert(0x8102);
        m_realtekNICIds.insert(0x8103);
        m_realtekNICIds.insert(0x8104);
        m_realtekNICIds.insert(0x8105);
        m_realtekNICIds.insert(0x8106);
        m_realtekNICIds.insert(0x8111);
        m_realtekNICIds.insert(0x8125);
    }

    std::vector<DeviceInfo> GetAllPCIDevices() {
        std::vector<DeviceInfo> devices;
        HDEVINFO deviceInfoSet = SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);

        if (deviceInfoSet == INVALID_HANDLE_VALUE) {
            std::cerr << "SetupDiGetClassDevs failed: " << GetLastError() << std::endl;
            return devices;
        }

        SP_DEVINFO_DATA deviceInfoData;
        deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

        for (DWORD i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) {
            DeviceInfo device;
            WCHAR instanceId[256];
            if (SetupDiGetDeviceInstanceId(deviceInfoSet, &deviceInfoData, instanceId, 256, NULL)) {
                char buf[256];
                WideCharToMultiByte(CP_ACP, 0, instanceId, -1, buf, 256, NULL, NULL);
                device.instanceId = buf;
                ParseHardwareId(buf, device.vendorId, device.deviceId);
            }

            WCHAR hardwareIds[512];
            if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, &deviceInfoData,
                SPDRP_HARDWAREID, NULL, (PBYTE)hardwareIds, sizeof(hardwareIds), NULL)) {
                char buf[512];
                WideCharToMultiByte(CP_ACP, 0, hardwareIds, -1, buf, 512, NULL, NULL);
                device.hardwareId = buf;
            }

            WCHAR desc[256];
            if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, &deviceInfoData,
                SPDRP_DEVICEDESC, NULL, (PBYTE)desc, sizeof(desc), NULL)) {
                char buf[256];
                WideCharToMultiByte(CP_ACP, 0, desc, -1, buf, 256, NULL, NULL);
                device.description = buf;
            }
            else {
                device.description = "Unknown Device";
            }

            ULONG status, problemNumber;
            if (CM_Get_DevNode_Status(&status, &problemNumber, deviceInfoData.DevInst, 0) == CR_SUCCESS) {
                device.problemCode = problemNumber;
                device.problemString = GetProblemString(problemNumber);
                device.hasDriver = (status & DN_DRIVER_LOADED) != 0;
            }
            else {
                device.problemCode = 0xFFFF;
                device.problemString = "Cannot get status";
                device.hasDriver = false;
            }

            devices.push_back(device);
        }

        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        return devices;
    }

    std::vector<DeviceInfo> DetectFakeRealtekNIC() {
        std::vector<DeviceInfo> fakeDevices;
        std::vector<DeviceInfo> allDevices = GetAllPCIDevices();

        for (const auto& device : allDevices) {
            if (device.instanceId.find("PCI\\") != 0) continue;
            if (device.vendorId != 0x10EC) continue;
            if (!IsRealtekNICDevice(device.deviceId)) continue;

            bool isFake = false;
            std::string reason;

            if (!device.hasDriver) {
                isFake = true;
                reason = "No driver loaded";
            }
            else if (device.problemCode == PROBLEM_DRIVER_FAILED) {
                isFake = true;
                reason = "Driver not installed (Code 28)";
            }
            else if (device.problemCode == PROBLEM_DRIVER_LOAD_FAILED) {
                isFake = true;
                reason = "Driver load failed (Code 31)";
            }

            if (isFake) {
                DeviceInfo devCopy = device;
                devCopy.problemString = reason;
                fakeDevices.push_back(devCopy);
            }
        }
        return fakeDevices;
    }

    std::vector<DeviceInfo> DetectAllSuspiciousDevices() {
        std::vector<DeviceInfo> suspicious;
        std::vector<DeviceInfo> allDevices = GetAllPCIDevices();

        for (const auto& device : allDevices) {
            if (device.instanceId.find("PCI\\") != 0) continue;
            if (device.problemCode == PROBLEM_DRIVER_FAILED ||
                device.problemCode == PROBLEM_DRIVER_LOAD_FAILED ||
                device.problemCode == PROBLEM_START_FAILED) {
                suspicious.push_back(device);
            }
        }
        return suspicious;
    }

    bool IsRealtekNICDevice(WORD deviceId) {
        return m_realtekNICIds.find(deviceId) != m_realtekNICIds.end();
    }

    void PrintDeviceInfo(const DeviceInfo& device, bool detailed = false) {
        std::cout << "  Device: " << device.description << std::endl;
        std::cout << "  Instance: " << device.instanceId << std::endl;
        if (detailed) {
            std::cout << "  Hardware: " << device.hardwareId << std::endl;
        }
        std::cout << "  VID/DID: 0x" << std::hex << device.vendorId
            << "/0x" << device.deviceId << std::dec << std::endl;
        std::cout << "  Status: " << device.problemString << std::endl;
        std::cout << "  Driver: " << (device.hasDriver ? "Loaded" : "NOT loaded") << std::endl;
    }

    void PrintSuspiciousDevices(const std::vector<DeviceInfo>& devices, const std::string& title) {
        if (devices.empty()) {
            std::cout << "[+] No " << title << " found." << std::endl;
            return;
        }

        std::cout << "\n[!!!] ===== " << title << " DETECTED =====" << std::endl;
        std::cout << "[!!!] Found " << devices.size() << " device(s):\n" << std::endl;

        for (size_t i = 0; i < devices.size(); i++) {
            std::cout << "  [" << (i + 1) << "] " << std::string(50, '-') << std::endl;
            PrintDeviceInfo(devices[i], true);
            std::cout << std::endl;
        }
        std::cout << "[!!!] ========================================\n" << std::endl;

        for (const auto& dev : devices) {
            m_attackHistory.push_back(dev);
        }
    }

    void PrintAllDevices() {
        auto devices = GetAllPCIDevices();
        std::cout << "\nAll PCI devices (" << devices.size() << " total):\n";
        std::cout << std::string(70, '-') << std::endl;

        int realtekCount = 0;
        for (const auto& dev : devices) {
            if (dev.instanceId.find("PCI\\") != 0) continue;

            std::string marker = "";
            if (dev.vendorId == 0x10EC && IsRealtekNICDevice(dev.deviceId)) {
                marker = " [Realtek NIC]";
                realtekCount++;
            }

            std::cout << "  " << dev.description
                << " (VID:0x" << std::hex << dev.vendorId
                << " DID:0x" << dev.deviceId << std::dec << ")"
                << " - Driver: " << (dev.hasDriver ? "OK" : "MISSING")
                << marker << std::endl;
        }
        std::cout << std::string(70, '-') << std::endl;
        std::cout << "Realtek NICs found: " << realtekCount << std::endl;
    }

    void SaveLog(const std::string& filename) {
        std::ofstream file(filename, std::ios::app);
        if (!file.is_open()) return;

        std::string timeStr = GetCurrentTimeString();
        file << "[" << timeStr << "] Scan completed" << std::endl;

        auto fakeDevices = DetectFakeRealtekNIC();
        if (!fakeDevices.empty()) {
            file << "!!! DMA ATTACK DETECTED !!!" << std::endl;
            for (const auto& dev : fakeDevices) {
                file << "  Device: " << dev.instanceId << std::endl;
                file << "  VID/DID: 0x" << std::hex << dev.vendorId
                    << "/0x" << dev.deviceId << std::dec << std::endl;
                file << "  Status: " << dev.problemString << std::endl;
            }
        }
        file << std::endl;
        file.close();
    }

    void PrintAttackHistory() {
        if (m_attackHistory.empty()) {
            std::cout << "\n[+] No attack history." << std::endl;
            return;
        }

        std::cout << "\n[!] Attack History (" << m_attackHistory.size() << " events):\n";
        std::cout << std::string(50, '-') << std::endl;
        for (size_t i = 0; i < m_attackHistory.size(); i++) {
            std::cout << "  Event " << (i + 1) << ":" << std::endl;
            PrintDeviceInfo(m_attackHistory[i]);
            std::cout << std::endl;
        }
    }

private:
    std::string GetProblemString(ULONG problemCode) {
        switch (problemCode) {
        case PROBLEM_NONE: return "Normal";
        case PROBLEM_DRIVER_FAILED: return "Driver not installed (Code 28)";
        case PROBLEM_DRIVER_LOAD_FAILED: return "Driver load failed (Code 31)";
        case PROBLEM_DISABLED: return "Device disabled";
        case PROBLEM_START_FAILED: return "Start failed (Code 10)";
        case PROBLEM_RESOURCE_CONFLICT: return "Resource conflict (Code 12)";
        case PROBLEM_DEVICE_REMOVED: return "Device removed";
        default: {
            char buf[32];
            sprintf_s(buf, "Code %lu", problemCode);
            return std::string(buf);
        }
        }
    }

    void ParseHardwareId(const std::string& instanceId, WORD& vid, WORD& did) {
        vid = did = 0;
        size_t venPos = instanceId.find("VEN_");
        size_t devPos = instanceId.find("DEV_");

        if (venPos != std::string::npos && venPos + 8 <= instanceId.length()) {
            std::string venStr = instanceId.substr(venPos + 4, 4);
            vid = (WORD)strtol(venStr.c_str(), NULL, 16);
        }

        if (devPos != std::string::npos && devPos + 8 <= instanceId.length()) {
            std::string devStr = instanceId.substr(devPos + 4, 4);
            did = (WORD)strtol(devStr.c_str(), NULL, 16);
        }
    }
};

// ==================== VT-d 监控类 ====================
class VTdMonitor {
private:
    HANDLE hDevice;
    bool connected;

public:
    VTdMonitor() : hDevice(INVALID_HANDLE_VALUE), connected(false) {}

    ~VTdMonitor() {
        Disconnect();
    }

    bool Connect() {
        hDevice = CreateFileA("\\\\.\\VTdMonitor",
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);

        if (hDevice == INVALID_HANDLE_VALUE) {
            return false;
        }
        connected = true;
        return true;
    }

    void Disconnect() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
        connected = false;
    }

    bool IsConnected() const {
        return connected;
    }

    bool GetVtdInfo(VTD_INFO& info) {
        if (!connected) return false;
        DWORD bytesReturned;
        return DeviceIoControl(hDevice, IOCTL_GET_VTD_INFO,
            NULL, 0, &info, sizeof(info), &bytesReturned, NULL);
    }

    bool GetVtdStatus(char* buffer, DWORD bufferSize) {
        if (!connected) return false;
        DWORD bytesReturned;
        return DeviceIoControl(hDevice, IOCTL_GET_VTD_STATUS,
            NULL, 0, buffer, bufferSize, &bytesReturned, NULL);
    }

    bool GetFaultEvent(FAULT_EVENT& event) {
        if (!connected) return false;
        DWORD bytesReturned;
        return DeviceIoControl(hDevice, IOCTL_GET_FAULT_EVENT,
            NULL, 0, &event, sizeof(event), &bytesReturned, NULL);
    }

    bool GetFaultCount(ULONG& count) {
        if (!connected) return false;
        DWORD bytesReturned;
        return DeviceIoControl(hDevice, IOCTL_GET_FAULT_COUNT,
            NULL, 0, &count, sizeof(count), &bytesReturned, NULL);
    }

    bool GetDebugOutput(char* buffer, DWORD bufferSize) {
        if (!connected) return false;
        DWORD bytesReturned;
        return DeviceIoControl(hDevice, IOCTL_GET_DEBUG_OUTPUT,
            NULL, 0, buffer, bufferSize, &bytesReturned, NULL);
    }

    void PrintVtdInfo() {
        VTD_INFO info;
        if (GetVtdInfo(info)) {
            std::cout << "\n========================================" << std::endl;
            std::cout << "VT-d Information" << std::endl;
            std::cout << "========================================" << std::endl;
            std::cout << "Status: " << info.StatusMessage << std::endl;
            std::cout << "VT-d Accessible: " << (info.VtdAccessible ? "Yes" : "No") << std::endl;
            std::cout << "VT-d Enabled: " << (info.VtDEnabled ? "Yes" : "No") << std::endl;
            std::cout << "VT-x Enabled: " << (info.VtXEnabled ? "Yes" : "No") << std::endl;
            std::cout << "Physical Base: 0x" << std::hex << info.PhysBase << std::dec << std::endl;
            std::cout << "Version: " << ((info.Version >> 4) & 0xF) << "." << (info.Version & 0xF) << std::endl;
            std::cout << "Capability: 0x" << std::hex << info.Capability << std::dec << std::endl;
            std::cout << "Fault Record Offset: 0x" << std::hex << info.FaultRegOffset << std::dec << std::endl;
            std::cout << "Number of Fault Records: " << info.NumFaultRegs << std::endl;
            std::cout << "========================================" << std::endl;
        }
        else {
            std::cout << "[-] Failed to get VT-d info. Make sure driver is loaded." << std::endl;
        }
    }

    void ShowDebugOutput() {
        char buffer[4096] = { 0 };
        if (GetDebugOutput(buffer, sizeof(buffer))) {
            std::cout << "\n========================================" << std::endl;
            std::cout << "Driver Debug Output" << std::endl;
            std::cout << "========================================" << std::endl;
            std::cout << buffer << std::endl;
            std::cout << "========================================" << std::endl;
        }
        else {
            std::cout << "[-] Failed to get debug output." << std::endl;
        }
    }

    void StartMonitoring() {
        if (!connected) {
            std::cout << "[-] VT-d monitor not connected. Please load driver first." << std::endl;
            return;
        }

        std::cout << "\n[*] VT-d DMA Fault Monitoring started..." << std::endl;
        std::cout << "[*] Waiting for DMA faults...\n" << std::endl;

        FAULT_EVENT event = { 0 };
        FAULT_EVENT lastEvent = { 0 };
        ULONG faultCount = 0;

        while (true) {
            if (GetFaultEvent(event)) {
                if (event.FaultAddress != lastEvent.FaultAddress ||
                    event.SourceId != lastEvent.SourceId) {

                    faultCount++;
                    const char* typeStr = (event.AccessType == 0) ? "Write" :
                        (event.AccessType == 1) ? "Read" : "PageReq";

                    std::cout << "\n========================================" << std::endl;
                    std::cout << "[!!!] DMA FAULT #" << faultCount << " DETECTED!" << std::endl;
                    std::cout << "========================================" << std::endl;
                    std::cout << "Fault Address: 0x" << std::hex << event.FaultAddress << std::dec << std::endl;
                    std::cout << "Access Type: " << typeStr << std::endl;
                    std::cout << "Fault Reason: 0x" << std::hex << (int)event.FaultReason << std::dec << std::endl;
                    std::cout << "Source BDF: " << std::hex << std::setw(2) << std::setfill('0')
                        << (int)event.Bus << ":" << std::setw(2) << (int)event.Device
                        << "." << (int)event.Function << std::dec << std::endl;
                    std::cout << "Device: " << event.DeviceDesc << std::endl;
                    std::cout << "========================================" << std::endl;

                    lastEvent = event;
                }
            }
            Sleep(100);
        }
    }
};

// ==================== 辅助函数 ====================
void PrintBanner() {
    std::cout << "================================================" << std::endl;
    std::cout << "   DMA Attack Detection System                  " << std::endl;
    std::cout << "   - PCI Device Scanner                         " << std::endl;
    std::cout << "   - VT-d DMA Fault Monitor                     " << std::endl;
    std::cout << "================================================" << std::endl;
}

void PrintMenu() {
    std::cout << "\n--------------------------------------------------------------------------------------------" << std::endl;
    std::cout << " Select option:                                                                             " << std::endl;
    std::cout << "  1. List all PCI devices                                                                   " << std::endl;
    std::cout << "  2. Detect all suspicious devices (no driver)                                              " << std::endl;
    std::cout << "  3. Detect fake Realtek NIC (DMA attack device)                                            " << std::endl;
    std::cout << "  4. Continuous monitoring (every 3 sec)                                                    " << std::endl;
    std::cout << "  5. Show attack history                                                                    " << std::endl;
    std::cout << "  6. Load VT-d Monitor Driver                                                               " << std::endl;
    std::cout << "  7. Show VT-d Information                                                                  " << std::endl;
    std::cout << "  8. Start VT-d DMA Fault Monitoring                                                        " << std::endl;
    std::cout << "  9. Show Driver Debug Output                                                               " << std::endl;
    std::cout << "  10. Exit                                                                                  " << std::endl;
    std::cout << "---------------------------------------------------------------------------------------------" << std::endl;
    std::cout << "Choice: ";
}

bool LoadVTdDriver() {
    HANDLE hDev = CreateFileA("\\\\.\\VTdMonitor",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDev != INVALID_HANDLE_VALUE) {
        CloseHandle(hDev);
        std::cout << "[+] VT-d driver already loaded." << std::endl;
        return true;
    }

    SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        std::cout << "[-] Failed to open Service Control Manager. Run as Administrator." << std::endl;
        return false;
    }

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string driverPath = std::string(exePath);
    size_t pos = driverPath.find_last_of("\\/");
    if (pos != std::string::npos) {
        driverPath = driverPath.substr(0, pos + 1) + "VTdMonitor.sys";
    }

    SC_HANDLE service = CreateServiceA(scManager, "VTdMonitor", "VTd Monitor",
        SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        driverPath.c_str(), NULL, NULL, NULL, NULL, NULL);

    if (!service) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            service = OpenServiceA(scManager, "VTdMonitor", SERVICE_START);
        }
        else {
            std::cout << "[-] Failed to create service. Error: " << GetLastError() << std::endl;
            CloseServiceHandle(scManager);
            return false;
        }
    }

    if (service) {
        if (StartServiceA(service, 0, NULL)) {
            std::cout << "[+] VT-d driver loaded successfully." << std::endl;
        }
        else {
            if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
                std::cout << "[+] VT-d driver already running." << std::endl;
            }
            else {
                std::cout << "[-] Failed to start driver. Error: " << GetLastError() << std::endl;
                std::cout << "[-] Make sure VTdMonitor.sys is in the same directory." << std::endl;
            }
        }
        CloseServiceHandle(service);
    }

    CloseServiceHandle(scManager);
    Sleep(1000);

    hDev = CreateFileA("\\\\.\\VTdMonitor", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDev != INVALID_HANDLE_VALUE) {
        CloseHandle(hDev);
        return true;
    }

    return false;
}

// ==================== 主函数 ====================
int main() {
    PrintBanner();

    RealtekDMADetector detector;
    VTdMonitor vtdMonitor;
    bool running = true;

    while (running) {
        PrintMenu();

        int choice;
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
        case 1: {
            detector.PrintAllDevices();
            break;
        }
        case 2: {
            std::cout << "\n[*] Scanning all suspicious devices..." << std::endl;
            auto suspicious = detector.DetectAllSuspiciousDevices();
            detector.PrintSuspiciousDevices(suspicious, "SUSPICIOUS PCI DEVICES");
            break;
        }
        case 3: {
            std::cout << "\n[*] Scanning for fake Realtek NIC..." << std::endl;
            auto fakeDevices = detector.DetectFakeRealtekNIC();
            detector.PrintSuspiciousDevices(fakeDevices, "FAKE REALTEK NIC");
            break;
        }
        case 4: {
            std::cout << "\n[*] Continuous monitoring started..." << std::endl;
            std::cout << "[*] Scanning every 3 seconds." << std::endl;
            std::cout << "[*] Insert your fake Realtek NIC to test detection.\n" << std::endl;

            int scanCount = 0;
            bool lastState = false;

            while (true) {
                scanCount++;
                auto fakeDevices = detector.DetectFakeRealtekNIC();
                bool currentState = !fakeDevices.empty();

                if (currentState && !lastState) {
                    std::cout << "\n[!!!] SCAN #" << scanCount << " - DMA ATTACK DETECTED!\n";
                    detector.PrintSuspiciousDevices(fakeDevices, "FAKE REALTEK NIC");
                    detector.SaveLog("dma_attack_log.txt");
                }
                else if (!currentState && lastState) {
                    std::cout << "\n[+] Attack device removed. System clean.\n";
                }
                else if (scanCount % 10 == 0) {
                    std::cout << "." << std::flush;
                }

                lastState = currentState;
                Sleep(3000);
            }
            break;
        }
        case 5: {
            detector.PrintAttackHistory();
            break;
        }
        case 6: {
            if (LoadVTdDriver()) {
                if (vtdMonitor.Connect()) {
                    std::cout << "[+] VT-d monitor connected successfully." << std::endl;
                }
                else {
                    std::cout << "[-] Failed to connect to VT-d monitor." << std::endl;
                }
            }
            else {
                std::cout << "[-] Failed to load VT-d driver." << std::endl;
                std::cout << "[-] Make sure you are running as Administrator." << std::endl;
                std::cout << "[-] And VTdMonitor.sys is in the same directory." << std::endl;
            }
            break;
        }
        case 7: {
            if (!vtdMonitor.IsConnected()) {
                std::cout << "[-] VT-d monitor not connected. Please select option 6 first." << std::endl;
            }
            else {
                vtdMonitor.PrintVtdInfo();
            }
            break;
        }
        case 8: {
            if (!vtdMonitor.IsConnected()) {
                std::cout << "[-] VT-d monitor not connected. Please select option 6 first." << std::endl;
            }
            else {
                vtdMonitor.StartMonitoring();
            }
            break;
        }
        case 9: {
            if (!vtdMonitor.IsConnected()) {
                std::cout << "[-] VT-d monitor not connected. Please select option 6 first." << std::endl;
            }
            else {
                vtdMonitor.ShowDebugOutput();
            }
            break;
        }
        case 10: {
            std::cout << "\n[+] Exiting...\n";
            running = false;
            break;
        }
        default: {
            std::cout << "[-] Invalid choice. Please try again.\n";
            break;
        }
        }
    }

    return 0;
}