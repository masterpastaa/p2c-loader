#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Winmm.lib")

#include <urlmon.h>
#include <tchar.h>
#include <sddl.h>
#include <stdio.h>
#include <string>
#include <strsafe.h>
#include <iostream>
#include <Windows.h>
#include <cstdlib>
#include <Lmcons.h>
#include "ManualMap.h"
#include "spoofer.h"
#include "console.h"
#include <filesystem>
#include <tchar.h>
#include <string>
#include <cstring>
#include <atlstr.h>
#include <windef.h>
#include <sstream>
#include <TlHelp32.h>
#include <thread>

using namespace std;
std::string id = "1";
std::string serial;
#define LENGTH(a) (sizeof(a) / sizeof(a[0]))



extern "C"
{
	BOOL AdjustCurrentPrivilege(LPCWSTR privilege);

	VOID ForceDeleteFile(LPWSTR path);

	void ChangePermission();
}

void StartThem1(LPCSTR name)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(name, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		return;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}
static const char alphanum[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

int stringLengthh = sizeof(alphanum) - 1;

char genRandomn()
{

	return alphanum[rand() % stringLengthh];
}
HWND consoleWindowHandle = GetConsoleWindow();
void HideConsole()
{
	::ShowWindow(::GetConsoleWindow(), SW_HIDE);
}

void ShowConsole()
{
	::ShowWindow(::GetConsoleWindow(), SW_SHOW);
}

bool IsConsoleVisible()
{
	return ::IsWindowVisible(::GetConsoleWindow()) != FALSE;
}

LPCSTR DllPath;
DWORD   ProcessId;
HANDLE hProcess;
int regedit() {
	system(_xor_("reg delete HKLM\\System\\CurrentControlSet\\Control\\TimeZoneInformation /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\Microsoft\\Windows\" \"NT\\CurrentVersion\\Notifications\\Data /v 418A073AA3BC3475 /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0 /f").c_str());
	system(_xor_("REG ADD HKCU\\Software\\Microsoft\\Direct3D /v WHQLClass /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName /v ComputerName /t REG_SZ /d DESKTOP-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName /v ComputerName /t REG_SZ /d DESKTOP-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v SusClientId /t REG_SZ /d Apple%random%-%random%-%random%-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\HardwareConfig /v LastConfig /t REG_SZ /d {Apple-%random%-%random} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\HardwareConfig\\Current /v BaseBoardProduct /t REG_SZ /d Apple-%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\Software\\Microsoft /v BuildLab /t REG_SZ /d Apple-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\Software\\Microsoft /v BuildLabEx /t REG_SZ /d Apple-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS /v BaseBoardProduct /t REG_SZ /d Apple-%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\kbdclass\\Parameters /v WppRecorder_TraceGuid /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\mouhid\\Parameters /v WppRecorder_TraceGuid /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 /v UserModeDriverGUID /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildBranch /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildGUID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildLab /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi\" \"Port\" \"0\\Scsi\" \"Bus\" \"0\\Target\" \"Id\" \"0\\Logical\" \"Unit\" \"Id\" \"0 /v Identifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi\" \"Port\" \"1\\Scsi\" \"Bus\" \"0\\Target\" \"Id\" \"0\\Logical\" \"Unit\" \"Id\" \"0 /v Identifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\0 /v Identifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\1 /v Identifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\BasicDisplay\\Video /v VideoID /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v MachineId /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v Hostname /t REG_SZ /d DESKTOP-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters /v Domain /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\System\\CurrentControlSet\\Control\\DevQuery\\6 /v UUID /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v NV\" \"Hostname /t REG_SZ /d DESKTOP-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware\" \"Profiles\\0001 /v HwProfileGuid /t REG_SZ /d {Apple%random%-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware\" \"Profiles\\0001 /v GUID /t REG_SZ /d {Apple%random%-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildGUID /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v REGisteredOwner /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v REGisteredOrganization /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Cryptography /v GUID /t REG_SZ /d %random%-%random%-%random%-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid /t REG_SZ /d Apple%random%-%random%-%random%-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v ProductId /t REG_SZ /d Apple%random%-%random%-%random%-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallDate /t REG_SZ /d Apple%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallTime /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildLabEx /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d {Apple%random%-%random%-%random%-%random%} /f").c_str());
	system(_xor_("REG delete HKCU\\Software\\Epic\" \"Games /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\Tracing\\Microsoft\\Profile\\Profile /v Guid /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Classes\\com.epicgames.launcher /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\WOW6432Node\\EpicGames /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\WOW6432Node\\Epic\" \"Games /f").c_str());
	system(_xor_("reg delete HKCR\\com.epicgames.launcher /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\MountedDevices /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Dfrg\\Statistics /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2 /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\LastEnum /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v AccountDomainSid /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v PingID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v SusClientId /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data /v SMBiosData /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\NVIDIA\" \"Corporation\\Global /v ClientUUID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\NVIDIA\" \"Corporation\\Global /v PersistenceIdentifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\NVIDIA\" \"Corporation\\Global\\CoProcManager /v ChipsetMatchID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\MountedDevices /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\com.epicgames.launcher /f").c_str());

	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Dfrg\\Statistics /f").c_str());
	system(_xor_("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume /f").c_str());
	system(_xor_("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume /f").c_str());
	system(_xor_("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2 /f").c_str());
	system(_xor_("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /v LastEnum /f").c_str());
	system(_xor_("REG ADD HKCU\\Software\\Classes\\Interface /v ClsidStore /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareIds /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v MachineId /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Classes\\Interface /v ClsidStore /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 /v _DriverProviderInfo /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 /v UserModeDriverGUID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v BackupProductKeyDefault /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v actionlist /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v ServiceSessionId /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Hex-Rays\\IDA\\History /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Hex-Rays\\IDA\\History64 /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v ServiceSessionId /f").c_str());

	system(_xor_("REG ADD HKCU\\Software\\Microsoft\\Direct3D /v WHQLClass /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKCU\\Software\\Classes\\Installer\\Dependencies /v MSICache /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI /v WindowsAIKHash /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v SusClientIdValidation /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKCU\\SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID /v RandomSeed /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Internet\" \"Explorer\\Migration /v IE\" \"Installed\" \"Date /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v DigitalProductId /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v DigitalProductId4 /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v WinSqmFirstSessionStartTime /t REG_QWORD /d %random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallTime /t REG_QWORD /d %random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallDate /t REG_QWORD /d %random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SevilleEventlogManager /v LastEventlogWrittenTime /t REG_QWORD /d %random%%random%%random% /f").c_str());

	system(_xor_("REG ADD HKLM\\System\\CurrentControlSet\\Control\\Notifications /v 418A073AA3BC8075 /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Kernel-EventTracing\/Admin /v OwningPublisher /t REG_SZ /d {%random%-%random%-%random%%random%} /f").c_str());;
	return TRUE;
}

void clean_launcher() {

	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Base.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseGame.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\WindowsGame.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseInput.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Portal\\Config\\UserLightmass.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\BaseWindowsLightmass.ini");
	DeleteFileW(L"C:\\Program Files(x86)\Epic Games\\Launcher\\Portal\\Config\\UserScalability.ini");
	DeleteFileW(L"C:\\Program Files(x86)\Epic Games\\Launcher\\Engine\\Config\\BaseHardware.ini");
	DeleteFileW(L"C:\\Program Files(x86)\Epic Games\\Launcher\\Portal\\Config\\NotForLicensees\\Windows\\WindowsHardware.ini");
}
void clean_net() {
	system(_xor_("start C:\\Windows\\IME\\network.exe").c_str());
	HideConsole();
	system(_xor_("netsh winsock reset").c_str());
	system(_xor_("netsh winsock reset catalog").c_str());
	system(_xor_("netsh int ip reset").c_str());
	system(_xor_("netsh advfirewall reset").c_str());
	system(_xor_("netsh int reset all").c_str());
	system(_xor_("netsh int ipv4 reset").c_str());
	system(_xor_("netsh int ipv6 reset").c_str());
	system(_xor_("ipconfig / release").c_str());
	system(_xor_("ipconfig / renew").c_str());
	system(_xor_("ipconfig / flushdns").c_str());
	CConsole::Clear();
	ShowConsole();
}
void clean_anticheat() {
	system(_xor_("reg delete HKLM\\SOFTWARE\\WOW6432Node\\EasyAntiCheat /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\ControlSet001\\Services\\EasyAntiCheat /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\ControlSet001\\Services\\BEService /f").c_str());
}
std::wstring GetCurrentUserName()
{
	wchar_t
		un[UNLEN + 1];
	DWORD unLen = UNLEN + 1;
	GetUserNameW(un, &unLen);
	return un;

}

void wipe_c() {
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q C:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\Public\\Documents").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\Prefetch").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q C:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q C:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q C:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\Intel").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());
}
void wipe_d() {
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q D:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\Public\\Documents").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q D:\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\Prefetch").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q D:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q D:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q D:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\Intel").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());
}
void wipe_e() {
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q E:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\Public\\Documents").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q E:\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\Prefetch").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q E:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q E:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q E:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\Intel").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());
}
void wipe_f() {
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q F:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\Public\\Documents").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q F:\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\Prefetch").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q F:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q F:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q F:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\Intel").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());

}


int clean() {
	
	return 0;
}

void suspend(DWORD processId)
{
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	Thread32First(hThreadSnapshot, &threadEntry);

	do
	{
		if (threadEntry.th32OwnerProcessID == processId)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
				threadEntry.th32ThreadID);

			SuspendThread(hThread);
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnapshot, &threadEntry));

	CloseHandle(hThreadSnapshot);
}

DWORD WINAPI Service_injector_Thread()
{
	DWORD Pid = 0;
	MODULEINFO Info;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HMODULE Kernel32 = 0;

	DWORD FileSize = 0, BytesRead = 0;
	PVOID pBuffer = 0;

	while (!(Pid = GetProcessid("notepad.exe")))
		Sleep(50);


	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Pid);

	if (hProcess == INVALID_HANDLE_VALUE || hProcess == 0)
	{
		std::cout << "Invalid Handle " << std::endl;
		return 0;
	}
	ManualMap* mapper = new ManualMap(g_fspoofer, sizeof(g_fspoofer), hProcess, Pid);

	if (mapper->MapDll())
		std::cout << "Inject Success " << std::endl;

	VirtualFree(pBuffer, 0, MEM_RELEASE);

	delete mapper;
	CloseHandle(hProcess);

	return 1;
}
#define SELF_REMOVE_STRING  TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")

void DelMe1()
{
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVE_STRING, szModuleName);

	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}
VOID __stdcall DoEnableSvc()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the service.

	schService = OpenService(
		schSCManager,            // SCM database 
		"Winmgmt",               // name of service 
		SERVICE_CHANGE_CONFIG);  // need change config access 

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}

	// Change the service start type.

	if (!ChangeServiceConfig(
		schService,            // handle of service 
		SERVICE_NO_CHANGE,     // service type: no change 
		SERVICE_DEMAND_START,  // service start type 
		SERVICE_NO_CHANGE,     // error control: no change 
		NULL,                  // binary path: no change 
		NULL,                  // load order group: no change 
		NULL,                  // tag ID: no change 
		NULL,                  // dependencies: no change 
		NULL,                  // account name: no change 
		NULL,                  // password: no change 
		NULL))                // display name: no change
	{
		printf("ChangeServiceConfig failed (%d)\n", GetLastError());
	}
	else printf("Service enabled successfully.\n");

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}
#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);



int auth();
void bsod()
{
	BOOLEAN bl;
	ULONG Response;
	RtlAdjustPrivilege(19, TRUE, FALSE, &bl); // Enable SeShutdownPrivilege
	NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response); // Shutdown
}

void DebuggerPresent()
{
	if (IsDebuggerPresent())
	{
		bsod();
	}
}

DWORD_PTR FindProcessId2(const std::string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

void ScanProccessListForBlacklistedProcess()
{
	if (FindProcessId2("ollydbg.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ProcessHacker.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("tcpview.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("autoruns.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("autorunsc.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("filemon.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("procmon.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("regmon.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("procexp.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("idaq.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("idaq64.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ImmunityDebugger.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Wireshark.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("dumpcap.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("HookExplorer.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ImportREC.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("PETools.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("LordPE.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("dumpcap.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("SysInspector.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("proc_analyzer.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("sysAnalyzer.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("sniff_hit.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("windbg.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("joeboxcontrol.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Fiddler.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("joeboxserver.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ida64.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ida.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Vmtoolsd.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Vmwaretrat.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Vmwareuser.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Vmacthlp.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("vboxservice.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("vboxtray.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("KsDumper.exe") != 0)
	{
	bsod();
	}
	else if (FindProcessId2("ReClass.NET.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("x64dbg.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("OLLYDBG.exe") != 0)
	{
		bsod();
	}
}

void ScanBlacklistedWindows()
{
	if (FindWindowA(NULL, _xor_("The Wireshark Network Analyzer").c_str()))
	{
		bsod();
	}

	if (FindWindowA(NULL, _xor_("Progress Telerik Fiddler Web Debugger").c_str()))
	{
		bsod();
	}

	if (FindWindowA(NULL, _xor_("x64dbg").c_str()))
	{
		bsod();
	}

	if (FindWindowA(NULL, _xor_("KsDumper").c_str()))
	{
		bsod();
	}
}

void AntiDebug()
{
	DebuggerPresent();
	ScanBlacklistedWindows();
	ScanProccessListForBlacklistedProcess();
}

int main()
{
	CConsole::SetRandomTitle();
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
	if (consoleWindowHandle) {
		SetWindowPos(
			consoleWindowHandle, // window handle
			HWND_TOPMOST, // "handle to the window to precede
						  // the positioned window in the Z order
						  // OR one of the following:"
						  // HWND_BOTTOM or HWND_NOTOPMOST or HWND_TOP or HWND_TOPMOST
			0, 0, // X, Y position of the window (in client coordinates)
			0, 0, // cx, cy => width & height of the window in pixels
			SWP_DRAWFRAME | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW // The window sizing and positioning flags.
		);
		// OPTIONAL ! - SET WINDOW'S "SHOW STATE"
		ShowWindow(
			consoleWindowHandle, // window handle
			SW_NORMAL // how the window is to be shown
					  // SW_NORMAL => "Activates and displays a window.
					  // If the window is minimized or maximized,
					  // the system restores it to its original size and position.
					  // An application should specify this flag
					  // when displaying the window for the first time."
		);
	}
	else {
	}
	system(_xor_("taskkill /f /im EpicGamesLauncher.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im FortniteClient-Win64-Shipping.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im OneDrive.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im RustClient.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im Origin.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im r5apex.exe >nul 2>&1").c_str());
	CConsole::Clear();
	S_LogType LogType;
	std::string HWID = GetHWID();
	Log(_xor_("Welcome to EngineOwning"), LogType.Info);
	Log(_xor_("Initializing"), LogType.Info);
	Log(_xor_("Connecting.."), LogType.Warning);
	CConsole::SetRandomTitle();
	Beep(523, 1000);

		char answ3r;
		Log(_xor_("Authed succefully"), LogType.Success);
		CConsole::SetRandomTitle();
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
		cout << "Do you want to clean for fortnite and apex traces?(Y/N): ";
		cin >> answ3r;
		if ((answ3r == 'y') || (answ3r == 'Y')) {
			Log(_xor_("Cleaning... (may take 1/5 minutes)"), LogType.Info);
			clean();
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);

			CConsole::Clear();

		}
		else
		{
		}
		Log(_xor_("engineowning.to"), LogType.Info);
		Log(_xor_("Initializing"), LogType.Info);
		Log(_xor_("Connecting.."), LogType.Warning);

		CConsole::SetRandomTitle();

		Log(_xor_("Authed succefully"), LogType.Success);
		CConsole::SetRandomTitle();
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);


		/*
		
		
		PUT YOUR LOADER HERE
		
		
		*/









	return 0;
}