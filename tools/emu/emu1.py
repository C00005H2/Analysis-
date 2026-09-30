#!/usr/bin/env python3
# Emulation harness: run the SecureEngine kernel (already unpacked into .winlice)
# from its entry 0x2FA44B4 under Unicorn, with Windows API shims.
import sys, struct, time, collections
sys.path.insert(0, '/tmp/retools')
import pefile
from unicorn import *
from unicorn.x86_const import *

PE_PATH = '/home/user/Analysis-/Test2.exe'
KERNEL = open('/tmp/test2_winlice_unpacked.bin','rb').read()
IMAGE_BASE = 0x400000
ENTRY = 0x2FA44B4

pe = pefile.PE(PE_PATH, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
SIZE_OF_IMAGE = pe.OPTIONAL_HEADER.SizeOfImage

# ---------------- fake module / stub plumbing ----------------
STUB_PAGE  = 0x7F000000          # each API stub = 16 bytes, body = 'ret'
STUB_LIMIT = 0x7F010000
stub_addr_of = {}                # name -> addr
addr_stub_of = {}                # addr -> name
_next_stub = [STUB_PAGE]
def get_stub(name):
    name = name.lower()
    if name not in stub_addr_of:
        a = _next_stub[0]; _next_stub[0] += 16
        stub_addr_of[name] = a; addr_stub_of[a] = name
    return stub_addr_of[name]

# module bases
MODS = {
 'kernel32.dll': 0x77E00000, 'ntdll.dll': 0x77C00000, 'user32.dll': 0x77D40000,
 'advapi32.dll': 0x77DD0000, 'version.dll': 0x77BC0000, 'shfolder.dll': 0x77BA0000,
 'shell32.dll': 0x7C9C0000, 'gdi32.dll': 0x77F10000, 'comctl32.dll': 0x773D0000,
 'imm32.dll': 0x76390000, 'winmm.dll': 0x76B40000, 'winspool.drv': 0x72D40000,
 'comdlg32.dll': 0x762C0000, 'oledlg.dll': 0x75E60000, 'ole32.dll': 0x774E0000,
 'oleaut32.dll': 0x77120000, 'shlwapi.dll': 0x77F60000, 'wsock32.dll': 0x71AD0000,
 'netapi32.dll': 0x5B860000, 'msvcrt.dll': 0x77C10000, 'imagehlp.dll': 0x76C90000,
}

MOD_EXPORTS = {}   # dllname -> {funcname_lower: (base, thunk_rva)}
ARENAS = {}        # base -> (arena_lo, arena_hi, thunk0)  (filled by build_fake_module)
THUNK_NAMES = {}   # base -> {thunk_rva: name}  (for resolution logging)
RESOLVED_LOG = []
WALKS = {}         # base -> current walk dict or None

# ---------------- comprehensive export name lists ----------------
K32_EXTRA = """ActivateActCtx AddAtomA AddAtomW AddRefActCtx AddVectoredContinueHandler
AddVectoredExceptionHandler AllocConsole AreFileApisANSI AssignProcessToJobObject
AttachConsole BackupRead BackupSeek BackupWrite BaseThreadInitThunk Beep
BeginUpdateResourceA BeginUpdateResourceW BindIoCompletionCallback BuildCommDCBA
BuildCommDCBAndTimeoutsA BuildCommDCBAndTimeoutsW BuildCommDCBW CallNamedPipeA
CallNamedPipeW CancelIo CancelIoEx CancelSynchronousIo CancelWaitableTimer
ChangeTimerQueueTimer CheckRemoteDebuggerPresent ClearCommBreak ClearCommError
CloseProfileUserMapping CommConfigDialogA CommConfigDialogW CompareFileTime
CompareStringA CompareStringW ConnectNamedPipe ConvertDefaultLocale
ConvertFiberToThread ConvertThreadToFiber CopyFileA CopyFileExA CopyFileExW CopyFileW
CreateActCtxA CreateActCtxW CreateConsoleScreenBuffer CreateDirectoryA
CreateDirectoryExA CreateDirectoryExW CreateDirectoryW CreateEventA CreateEventW
CreateFiber CreateFiberEx CreateFileA CreateFileMappingA CreateFileMappingW CreateFileW
CreateHardLinkA CreateHardLinkW CreateIoCompletionPort CreateJobObjectA CreateJobObjectW
CreateMailslotA CreateMailslotW CreateMemoryResourceNotification CreateMutexA CreateMutexW
CreateNamedPipeA CreateNamedPipeW CreatePipe CreateProcessA CreateProcessAsUserA
CreateProcessAsUserW CreateProcessW CreateRemoteThread CreateRemoteThreadEx
CreateSemaphoreA CreateSemaphoreW CreateTapePartition CreateThread CreateTimerQueue
CreateTimerQueueTimer CreateToolhelp32Snapshot CreateWaitableTimerA CreateWaitableTimerW
DeactivateActCtx DecodePointer DecodeSystemPointer DefineDosDeviceA DefineDosDeviceW
DeleteAtom DeleteFiber DeleteFileA DeleteFileW DeleteTimerQueue DeleteTimerQueueEx
DeleteTimerQueueTimer DeleteVolumeMountPointA DeleteVolumeMountPointW DeviceIoControl
DisableThreadLibraryCalls DisconnectNamedPipe DnsHostnameToComputerNameA
DnsHostnameToComputerNameW DosDateTimeToFileTime DuplicateHandle EncodePointer
EncodeSystemPointer EndUpdateResourceA EndUpdateResourceW EnumCalendarInfoA
EnumCalendarInfoExA EnumCalendarInfoExW EnumCalendarInfoW EnumDateFormatsA
EnumDateFormatsExA EnumDateFormatsExW EnumDateFormatsW EnumResourceLanguagesA
EnumResourceLanguagesW EnumResourceNamesA EnumResourceNamesW EnumResourceTypesA
EnumResourceTypesW EnumSystemCodePagesA EnumSystemCodePagesW EnumSystemLocalesA
EnumSystemLocalesW EnumTimeFormatsA EnumTimeFormatsW EnumUILanguagesA EnumUILanguagesW
EscapeCommFunction ExitWindowsEx FatalAppExitA FatalAppExitW FileTimeToDosDateTime
FileTimeToLocalFileTime FileTimeToSystemTime FindActCtxSectionGuid
FindActCtxSectionStringA FindActCtxSectionStringW FindAtomA FindAtomW FindClose
FindCloseChangeNotification FindFirstChangeNotificationA FindFirstChangeNotificationW
FindFirstFileA FindFirstFileExA FindFirstFileExW FindFirstFileW FindFirstVolumeA
FindFirstVolumeW FindNextChangeNotification FindNextFileA FindNextFileW FindNextVolumeA
FindNextVolumeW FindResourceA FindResourceExA FindResourceExW FindResourceW
FlushConsoleInputBuffer FlushFileBuffers FlushViewOfFile FoldStringA FoldStringW
FormatMessageA FormatMessageW FreeConsole FreeEnvironmentStringsA FreeEnvironmentStringsW
FreeLibraryAndExitThread FreeResource GenerateConsoleCtrlEvent GetACP GetAtomNameA
GetAtomNameW GetBinaryTypeA GetBinaryTypeW GetCalendarInfoA GetCalendarInfoW
GetCommandLineW GetCompressedFileSizeA GetCompressedFileSizeW GetComputerNameA
GetComputerNameExA GetComputerNameExW GetComputerNameW GetConsoleCP GetConsoleCursorInfo
GetConsoleMode GetConsoleOutputCP GetConsoleScreenBufferInfo GetConsoleTitleA
GetConsoleTitleW GetConsoleWindow GetCPInfo GetCPInfoExA GetCPInfoExW GetCurrentActCtx
GetCurrentConsoleFont GetCurrentDirectoryA GetCurrentDirectoryW GetCurrentThread
GetDateFormatA GetDateFormatW GetDefaultCommConfigA GetDefaultCommConfigW
GetDiskFreeSpaceA GetDiskFreeSpaceExA GetDiskFreeSpaceExW GetDiskFreeSpaceW
GetDllDirectoryA GetDllDirectoryW GetDriveTypeA GetDriveTypeW GetEnvironmentStrings
GetEnvironmentStringsA GetEnvironmentStringsW GetExitCodeProcess GetExitCodeThread
GetFileAttributesA GetFileAttributesExA GetFileAttributesExW GetFileAttributesW
GetFileInformationByHandle GetFileSizeEx GetFileTime GetFileType
GetFirmwareEnvironmentVariableA GetFirmwareEnvironmentVariableW GetFullPathNameA
GetFullPathNameW GetHandleCount GetHandleInformation GetLargestConsoleWindowSize
GetLocaleInfoA GetLocaleInfoW GetLogicalDriveStringsA GetLogicalDriveStringsW
GetLongPathNameA GetLongPathNameW GetMailslotInfo GetModuleFileNameW GetModuleHandleW
GetModuleHandleExA GetModuleHandleExW GetNamedPipeHandleStateA GetNamedPipeHandleStateW
GetNamedPipeInfo GetNativeSystemInfo GetNumberFormatA GetNumberFormatW
GetNumberOfConsoleInputEvents GetNumberOfConsoleMouseButtons GetOEMCP GetOverlappedResult
GetPrivateProfileIntA GetPrivateProfileIntW GetPrivateProfileSectionA
GetPrivateProfileSectionNamesA GetPrivateProfileSectionNamesW GetPrivateProfileSectionW
GetPrivateProfileStringA GetPrivateProfileStringW GetPrivateProfileStructA
GetPrivateProfileStructW GetProcessAffinityMask GetProcessHeaps GetProcessId
GetProcessIoCounters GetProcessPriorityBoost GetProcessShutdownParameters GetProcessTimes
GetProcessWorkingSetSize GetProductInfo GetProfileIntA GetProfileIntW GetProfileSectionA
GetProfileSectionW GetProfileStringA GetProfileStringW GetQueuedCompletionStatus
GetQueuedCompletionStatusEx GetShortPathNameA GetShortPathNameW GetStartupInfoA
GetStartupInfoW GetStringTypeA GetStringTypeExA GetStringTypeExW GetStringTypeW
GetSystemDefaultLangID GetSystemDefaultLCID GetSystemDefaultUILanguage
GetSystemFileCacheSize GetSystemPowerStatus GetSystemRegistryQuota
GetSystemTimeAdjustment GetSystemTimeAsFileTime GetSystemTimes GetSystemWow64DirectoryA
GetSystemWow64DirectoryW GetTapeParameters GetTapePosition GetTapeStatus GetTempFileNameA
GetTempFileNameW GetTempPathA GetTempPathW GetThreadIOPendingFlag GetThreadLocale
GetThreadPriority GetThreadPriorityBoost GetThreadSelectorEntry GetThreadTimes
GetTickCount64 GetTimeFormatA GetTimeFormatW GetTimeZoneInformation GetUserDefaultLangID
GetUserDefaultLCID GetUserDefaultUILanguage GetUserGeoID GetVersion GetVersionExA
GetVersionExW GetVolumeInformationA GetVolumeInformationW
GetVolumeNameForVolumeMountPointA GetVolumeNameForVolumeMountPointW GetVolumePathNameA
GetVolumePathNameW GetVolumePathNamesForVolumeNameA GetVolumePathNamesForVolumeNameW
GetWriteWatch GlobalAddAtomA GlobalAddAtomW GlobalDeleteAtom GlobalFindAtomA
GlobalFindAtomW GlobalFlags GlobalGetAtomNameA GlobalGetAtomNameW GlobalHandle
GlobalMemoryStatusEx GlobalReAlloc GlobalUnfix GlobalUnlock HeapCompact HeapCreate
HeapDestroy HeapLock HeapReAlloc HeapSetInformation HeapSize HeapUnlock HeapValidate
HeapWalk InitAtomTable InitializeCriticalSectionAndSpinCount InitializeSListHead
InterlockedCompareExchange InterlockedCompareExchange64 InterlockedExchange
InterlockedExchangeAdd InterlockedFlushSList InterlockedPopEntrySList
InterlockedPushEntrySList InterlockedPushListSList IsBadCodePtr IsBadHugeReadPtr
IsBadHugeWritePtr IsBadReadPtr IsBadStringPtrA IsBadStringPtrW IsBadWritePtr
IsProcessInJob IsSystemResumeAutomatic IsThreadAFiber IsValidCodePage
IsValidLanguageGroup IsValidLocale IsValidUILanguage K32GetProcessMemoryInfo
LCMapStringA LCMapStringW LoadLibraryExA LoadLibraryExW LoadLibraryW LoadModule
LoadResource LocalFileTimeToFileTime LocalFlags LocalHandle LocalReAlloc LockFile
LockFileEx LockResource lstrcatA lstrcatW lstrcmpiA lstrcmpiW lstrcmpW lstrcpynA
lstrcpynW lstrcpyW lstrlenW MapUserPhysicalPages MapUserPhysicalPagesScatter
MapViewOfFileEx Module32First Module32FirstW Module32Next Module32NextW MoveFileA
MoveFileExA MoveFileExW MoveFileW MoveFileWithProgressA MoveFileWithProgressW MulDiv
NeedCurrentDirectoryForExePathA NeedCurrentDirectoryForExePathW OpenEventA OpenEventW
OpenFile OpenFileMappingA OpenFileMappingW OpenJobObjectA OpenJobObjectW OpenMutexA
OpenMutexW OpenProfileUserMapping OpenSemaphoreA OpenSemaphoreW OpenThread
OpenWaitableTimerA OpenWaitableTimerW PeekConsoleInputA PeekConsoleInputW PeekNamedPipe
PostQueuedCompletionStatus PrepareTape ProcessIdToSessionId Process32First
Process32FirstW Process32Next Process32NextW PulseEvent PurgeComm QueryActCtxW
QueryDepthSList QueryDosDeviceA QueryDosDeviceW QueryInformationJobObject
QueryPerformanceFrequency QueueUserAPC QueueUserWorkItem RaiseException
RaiseFailFastException ReadConsoleA ReadConsoleInputA ReadConsoleInputW ReadConsoleW
ReadDirectoryChangesW ReadFileEx ReadFileScatter ReleaseActCtx ReleaseMutex
ReleaseSemaphore RemoveDirectoryA RemoveDirectoryW RemoveVectoredContinueHandler
RemoveVectoredExceptionHandler ReplaceFileA ReplaceFileW ResetEvent ResetWriteWatch
ResumeThread RtlCaptureContext RtlCaptureStackBackTrace RtlFillMemory RtlMoveMemory
RtlUnwind RtlZeroMemory ScrollConsoleScreenBufferA ScrollConsoleScreenBufferW
SearchPathA SearchPathW SetCalendarInfoA SetCalendarInfoW SetCommBreak SetCommConfigA
SetCommConfigW SetCommMask SetCommState SetCommTimeouts SetComputerNameA
SetComputerNameExA SetComputerNameExW SetComputerNameW SetConsoleActiveScreenBuffer
SetConsoleCP SetConsoleCursorInfo SetConsoleCursorPosition SetConsoleMode
SetConsoleOutputCP SetConsoleScreenBufferSize SetConsoleTextAttribute SetConsoleTitleA
SetConsoleTitleW SetConsoleWindowInfo SetCriticalSectionSpinCount SetCurrentDirectoryA
SetCurrentDirectoryW SetDefaultCommConfigA SetDefaultCommConfigW SetDllDirectoryA
SetDllDirectoryW SetEndOfFile SetFileApisToANSI SetFileApisToOEM SetFilePointerEx
SetFileShortNameA SetFileShortNameW SetFileTime SetFileValidData
SetFirmwareEnvironmentVariableA SetFirmwareEnvironmentVariableW SetHandleCount
SetHandleInformation SetInformationJobObject SetLocalTime SetLocaleInfoA
SetLocaleInfoW SetMailslotInfo SetMessageWaitingIndicator SetNamedPipeHandleStateA
SetNamedPipeHandleStateW SetProcessAffinityMask SetProcessPriorityBoost
SetProcessShutdownParameters SetProcessTimes SetProcessWorkingSetSize SetStdHandle
SetSystemFileCacheSize SetSystemPowerState SetSystemTime SetSystemTimeAdjustment
SetTapeParameters SetTapePosition SetThreadAffinityMask SetThreadExecutionState
SetThreadIdealProcessor SetThreadLocale SetThreadPriorityBoost SetThreadUILanguage
SetTimerQueueTimer SetTimeZoneInformation SetVolumeLabelA SetVolumeLabelW
SetVolumeMountPointA SetVolumeMountPointW SetWaitableTimer SetupComm
SignalObjectAndWait SizeofResource SleepEx SwitchToFiber SwitchToThread
SystemTimeToFileTime SystemTimeToTzSpecificLocalTime TerminateJobObject TerminateThread
Thread32First Thread32Next Toolhelp32ReadProcessMemory TransactNamedPipe
TransmitCommChar TryEnterCriticalSection TzSpecificLocalTimeToSystemTime
UnhandledExceptionFilter UnlockFile UnlockFileEx UnmapViewOfFile UpdateResourceA
UpdateResourceW ValidateLocale VerLanguageNameA VerLanguageNameW VerifyVersionInfoA
VerifyVersionInfoW VirtualAllocEx VirtualFreeEx VirtualLock VirtualProtectEx
VirtualQueryEx VirtualUnlock WaitCommEvent WaitForMultipleObjects
WaitForMultipleObjectsEx WaitForSingleObjectEx WaitNamedPipeA WaitNamedPipeW
WideCharToMultiByte WinExec Wow64DisableWow64FsRedirection Wow64EnableWow64FsRedirection
Wow64GetThreadContext Wow64RevertWow64FsRedirection Wow64SetThreadContext
WriteConsoleA WriteConsoleInputA WriteConsoleInputW WriteConsoleOutputA
WriteConsoleOutputAttribute WriteConsoleOutputCharacterA WriteConsoleOutputCharacterW
WriteConsoleOutputW WriteConsoleW WriteFileEx WriteFileGather
WritePrivateProfileSectionA WritePrivateProfileSectionW WritePrivateProfileStringA
WritePrivateProfileStringW WritePrivateProfileStructA WritePrivateProfileStructW
WriteProfileSectionA WriteProfileSectionW WriteProfileStringA WriteProfileStringW
WriteTapemark ZombifyActCtx GetSystemWindowsDirectoryA GetSystemWindowsDirectoryW"""
# merge the complete Win7 export lists (fetched from win7dll.info)
K32_EXTRA = K32_EXTRA.split() + open('/tmp/k32_win7_all.txt').read().split()

NT_EXTRA = """NtQueryInformationProcess NtQuerySystemInformation NtSetInformationThread
NtAllocateVirtualMemory NtFreeVirtualMemory NtProtectVirtualMemory NtQueryVirtualMemory
RtlAllocateHeap RtlFreeHeap RtlInitUnicodeString LdrLoadDll LdrGetProcedureAddress
NtClose NtContinue NtCreateFile NtOpenFile NtReadFile NtWriteFile NtOpenProcess
NtTerminateProcess NtQueryInformationFile NtSetInformationFile NtQueryAttributesFile
NtOpenDirectoryObject NtQueryDirectoryObject RtlImageNtHeader RtlImageDirectoryEntryToData
RtlAddVectoredExceptionHandler RtlRemoveVectoredExceptionHandler RtlUnwindEx
RtlDecompressBuffer RtlCompareMemory LdrGetDllHandle NtYieldExecution DbgBreakPoint
DbgUiRemoteBreakin KiUserExceptionDispatcher NtCurrentTeb RtlReAllocateHeap
RtlSizeHeap NtDelayExecution NtQueryPerformanceCounter NtQuerySystemTime
NtWaitForSingleObject NtWaitForMultipleObjects NtSignalAndWaitForSingleObject
NtCreateEvent NtSetEvent NtResetEvent NtOpenEvent NtQueryEvent RtlEnterCriticalSection
RtlLeaveCriticalSection RtlInitializeCriticalSection NtOpenKey NtQueryValueKey
NtCreateKey NtSetValueKey NtEnumerateKey NtQueryKey NtFlushKey NtClose RtlFreeUnicodeString
RtlAnsiStringToUnicodeString RtlUnicodeStringToAnsiString memcpy memcmp strlen strcpy
NtGetContextThread NtSetContextThread NtResumeThread NtSuspendThread NtCreateThread
NtCreateThreadEx NtOpenThread NtTerminateThread NtQueryDirectoryFile NtDuplicateObject
NtQueryObject NtSetDebugFilterState LdrEnumerateLoadedModules RtlDosPathNameToNtPathName_U"""
U32_EXTRA = """ActivateKeyboardLayout AdjustWindowRect AdjustWindowRectEx AllowSetForegroundWindow
AnimateWindow AnyPopup AppendMenuA AppendMenuW ArrangeIconicWindows AttachThreadInput
BeginDeferWindowPos BeginPaint BlockInput BringWindowToTop BroadcastSystemMessage
BroadcastSystemMessageA BroadcastSystemMessageExA BroadcastSystemMessageExW
BroadcastSystemMessageW CalculatePopupWindowPosition CallMsgFilter CallMsgFilterA
CallMsgFilterW CallNextHookEx CallWindowProcA CallWindowProcW CascadeWindows
ChangeClipboardChain ChangeDisplaySettingsA ChangeDisplaySettingsExA
ChangeDisplaySettingsExW ChangeDisplaySettingsW CharLowerA CharLowerBuffA
CharLowerBuffW CharLowerW CharNextA CharNextExA CharNextW CharPrevA CharPrevExA
CharPrevW CharToOemA CharToOemBuffA CharToOemBuffW CharToOemW CharUpperA CharUpperBuffA
CharUpperBuffW CharUpperW CheckDlgButton CheckMenuItem CheckMenuRadioItem CheckRadioButton
ChildWindowFromPoint ChildWindowFromPointEx ClientToScreen ClipCursor CloseClipboard
CloseDesktop CloseWindow CloseWindowStation CopyAcceleratorTableA CopyAcceleratorTableW
CopyIcon CopyImage CopyRect CountClipboardFormats CreateAcceleratorTableA
CreateAcceleratorTableW CreateCaret CreateCursorA CreateCursorW CreateDesktopA CreateDesktopW
CreateDialogIndirectParamA CreateDialogIndirectParamW CreateDialogParamA CreateDialogParamW
CreateIcon CreateIconFromResource CreateIconFromResourceEx CreateIconIndirect
CreateMDIWindowA CreateMDIWindowW CreateMenu CreatePatternBrush? CreatePopupMenu
CreateWindowExA CreateWindowExW CreateWindowStationA CreateWindowStationW DefDlgProcA
DefDlgProcW DeferWindowPos DefFrameProcA DefFrameProcW DefMDIChildProcA DefMDIChildProcW
DefWindowProcA DefWindowProcW DeleteMenu DestroyAcceleratorTable DestroyCaret
DestroyCursor DestroyIcon DestroyMenu DestroyWindow DialogBoxIndirectParamA
DialogBoxIndirectParamW DialogBoxParamA DialogBoxParamW DispatchMessageA DispatchMessageW
DragDetect DrawAnimatedRects DrawCaption DrawEdge DrawFocusRect DrawFrameControl
DrawIcon DrawIconEx DrawMenuBar DrawTextA DrawTextExA DrawTextExW DrawTextW
EmptyClipboard EnableMenuItem EnableNonClientDPL? EnableScrollBar EnableWindow
EndDeferWindowPos EndMenu EndPaint EnumChildWindows EnumClipboardFormats EnumDesktopsA
EnumDesktopsW EnumDesktopWindows EnumDisplayDevicesA EnumDisplayDevicesW
EnumDisplayMonitors EnumDisplaySettingsA EnumDisplaySettingsExA EnumDisplaySettingsExW
EnumDisplaySettingsW EnumPropsA EnumPropsExA EnumPropsExW EnumPropsW EnumThreadWindows
EnumWindowStationsA EnumWindowStationsW EnumWindows EqualRect ExcludeUpdateRgn
FillRect FindWindowA FindWindowExA FindWindowExW FindWindowW FlashWindow FlashWindowEx
FrameRect GetActiveWindow GetAncestor GetAsyncKeyState GetCapture GetCaretBlinkTime
GetCaretPos GetClassInfoA GetClassInfoExA GetClassInfoExW GetClassInfoW GetClassLongA
GetClassLongPtrA GetClassLongPtrW GetClassLongW GetClassNameA GetClassNameW
GetClassWord GetClientRect GetClipboardData GetClipboardFormatNameA
GetClipboardFormatNameW GetClipboardOwner GetClipboardSequenceNumber GetClipboardViewer
GetComboBoxInfo GetCursor GetCursorInfo GetCursorPos GetDC GetDCEx GetDesktopWindow
GetDialogBaseUnits GetDlgCtrlID GetDlgItem GetDlgItemInt GetDlgItemTextA GetDlgItemTextW
GetDoubleClickTime GetFocus GetForegroundWindow GetGUIThreadInfo GetIconInfo
GetInputState GetKBCodePage GetKeyboardLayout GetKeyboardLayoutList
GetKeyboardLayoutNameA GetKeyboardLayoutNameW GetKeyboardState GetKeyboardType
GetKeyNameTextA GetKeyNameTextW GetKeyState GetLastActivePopup GetListBoxInfo
GetMenu GetMenuBarInfo GetMenuCheckMarkDimensions GetMenuContextHelpId? GetMenuDefaultItem
GetMenuInfo GetMenuItemCount GetMenuItemID GetMenuItemInfoA GetMenuItemInfoW
GetMenuItemRect GetMenuState GetMenuStringA GetMenuStringW GetMessageA GetMessageExtraInfo
GetMessagePos GetMessageTime GetMessageW GetMonitorInfoA GetMonitorInfoW GetMouseMovePointsEx
GetNextDlgGroupItem GetNextDlgTabItem GetOpenClipboardWindow GetParent GetPriorityClipboardFormat
GetProcessDefaultLayout GetProcessWindowStation GetPropA GetPropW GetQueueStatus
GetScrollBarInfo GetScrollInfo GetScrollPos GetScrollRange GetShellWindow GetSubMenu
GetSysColor GetSysColorBrush GetSystemMenu GetSystemMetrics GetTabbedTextExtentA
GetTabbedTextExtentW GetThreadDesktop GetThreadPriority? GetTitleBarInfo GetTopWindow
GetUpdateRect GetUpdateRgn GetUserObjectInformationA GetUserObjectInformationW
GetUserObjectSecurity GetWindow GetWindowContextHelpId GetWindowDC GetWindowInfo
GetWindowLongA GetWindowLongPtrA GetWindowLongPtrW GetWindowLongW GetWindowModuleFileNameA
GetWindowModuleFileNameW GetWindowPlacement GetWindowRect GetWindowRgn GetWindowRgnBox
GetWindowTextA GetWindowTextLengthA GetWindowTextLengthW GetWindowTextW
GetWindowThreadProcessId GetWindowWord GrayStringA GrayStringW HideCaret HiliteMenuItem
InflateRect InsertMenuItemA InsertMenuItemW InsertMenuA InsertMenuW InternalGetWindowText
InvalidateRect InvalidateRgn IsCharAlphaA IsCharAlphaNumericA IsCharAlphaNumericW
IsCharAlphaW IsCharLowerA IsCharLowerW IsCharUpperA IsCharUpperW IsChild IsClipboardFormatAvailable
IsDialogMessageA IsDialogMessageW IsDlgButtonChecked IsGUIThread IsIconic IsMenu
IsProcessDPIAware IsRectEmpty IsTouchWindow IsValidIconHandle? IsValidCodePtr?
IsWindow IsWindowEnabled IsWindowUnicode IsWindowVisible IsWinEventHookInstalled? IsZoomed
keybd_event KillTimer LoadAcceleratorsA LoadAcceleratorsW LoadBitmapA LoadBitmapW
LoadCursorA LoadCursorFromFileA LoadCursorFromFileW LoadCursorW LoadIconA LoadIconW
LoadImageA LoadImageW LoadKeyboardLayoutA LoadKeyboardLayoutW LoadMenuA LoadMenuIndirectA
LoadMenuIndirectW LoadMenuW LoadStringA LoadStringW LockWindowUpdate LockWorkStation
LogicalToPhysicalPoint LookupIconIdFromDirectory LookupIconIdFromDirectoryEx MapDialogRect
MapVirtualKeyA MapVirtualKeyExA MapVirtualKeyExW MapVirtualKeyW MapWindowPoints
MenuItemFromPoint MessageBoxA MessageBoxExA MessageBoxExW MessageBoxIndirectA
MessageBoxIndirectW MessageBoxW ModifyMenuA ModifyMenuW MonitorFromPoint MonitorFromRect
MonitorFromWindow mouse_event MoveWindow MsgWaitForMultipleObjects
MsgWaitForMultipleObjectsEx NotifyWinEvent OffsetRect OemKeyScan OemToCharA OemToCharBuffA
OemToCharBuffW OemToCharW OpenClipboard OpenDesktopA OpenDesktopW OpenIcon
OpenInputDesktop OpenWindowStationA OpenWindowStationW PaintDesktop PeekMessageA PeekMessageW
PhysicalToLogicalPoint PostMessageA PostMessageW PostQuitMessage PostThreadMessageA
PostThreadMessageW PrintWindow PtInRect RedrawWindow RegisterClassA RegisterClassExA
RegisterClassExW RegisterClassW RegisterClipboardFormatA RegisterClipboardFormatW
RegisterHotKey RegisterWindowMessageA RegisterWindowMessageW ReleaseCapture ReleaseDC
RemoveMenu RemovePropA RemovePropW ReplyMessage ScreenToClient ScrollDC ScrollWindow
ScrollWindowEx SendDlgItemMessageA SendDlgItemMessageW SendInput SendMessageA
SendMessageCallbackA SendMessageCallbackW SendMessageTimeoutA SendMessageTimeoutW
SendMessageW SendNotifyMessageA SendNotifyMessageW SetActiveWindow SetCapture SetCaretBlinkTime
SetCaretPos SetClassLongA SetClassLongPtrA SetClassLongPtrW SetClassLongW SetClassWord
SetClipboardData SetClipboardViewer SetCursor SetCursorPos SetDebugErrorLevel?
SetDlgItemInt SetDlgItemTextA SetDlgItemTextW SetDoubleClickTime SetFocus SetForegroundWindow
SetKeyboardState SetLastErrorEx? SetMenu SetMenuDefaultItem SetMenuInfo SetMenuItemBitmaps
SetMenuItemInfoA SetMenuItemInfoW SetMessageExtraInfo SetParent SetProcessDPIAware
SetProcessDefaultLayout SetPropA SetPropW SetRect SetRectEmpty SetScrollInfo SetScrollPos
SetScrollRange SetSysColors SetSystemCursor SetSystemMenu? SetThreadDesktop SetTimer
SetUserObjectInformationA SetUserObjectInformationW SetUserObjectSecurity SetWindowContextHelpId?
SetWindowLongA SetWindowLongPtrA SetWindowLongPtrW SetWindowLongW SetWindowPlacement
SetWindowPos SetWindowRgn SetWindowTextA SetWindowTextW SetWindowWord ShowCaret
ShowCursor ShowOwnedPopups ShowScrollBar ShowWindow ShowWindowAsync SubtractRect
SwapMouseButton SwitchToThisWindow SystemParametersInfoA SystemParametersInfoW
TabbedTextOutA TabbedTextOutW TileWindows ToAscii ToAsciiEx ToUnicode ToUnicodeEx
TrackMouseEvent TrackPopupMenu TrackPopupMenuEx TranslateAcceleratorA TranslateAcceleratorW
TranslateMDISysMenu TranslateMessage UnhookWindowsHookEx UnhookWinEvent UnregisterClassA
UnregisterClassW UnregisterHotKey UpdateWindow ValidateRect ValidateRgn
VkKeyScanA VkKeyScanExA VkKeyScanExW VkKeyScanW WaitForInputIdle WindowFromDC
WindowFromPoint WinHelpA WinHelpW wsprintfA wsprintfW wvsprintfA wvsprintfW"""
ADV_EXTRA = """AbortSystemShutdownA AbortSystemShutdownW AccessCheck AccessCheckAndAuditAlarmA
AccessCheckAndAuditAlarmW AddAccessAllowedAce AddAccessDeniedAce AddAce AddAuditAccessAce
AdjustTokenGroups AdjustTokenPrivileges AllocateAndInitializeSid AllocateLocallyUniqueId
AreAllAccessesGranted AreAnyAccessesGranted BackupEventLogA BackupEventLogW
BuildExplicitAccessWithNameA BuildExplicitAccessWithNameW BuildImpersonateExplicitAccessWithName?
ChangeServiceConfigA ChangeServiceConfigW CheckTokenMembership ClearEventLogA ClearEventLogW
CloseEncryptedFileRaw CloseServiceHandle ControlService ConvertSidToStringSidA
ConvertSidToStringSidW ConvertStringSecurityDescriptorToSecurityDescriptorA
ConvertStringSecurityDescriptorToSecurityDescriptorW ConvertStringSidToSidA
ConvertStringSidToSidW CopySid CreatePrivateObjectSecurity CreateProcessAsUserA
CreateProcessAsUserW CreateRestrictedToken CreateServiceA CreateServiceW
CryptAcquireContextA CryptAcquireContextW CryptCreateHash CryptDeriveKey CryptDestroyHash
CryptDestroyKey CryptEncrypt CryptDecrypt CryptGenKey CryptGetHashParam CryptHashData
CryptReleaseContext CryptSetHashParam DecryptFileA DecryptFileW DeleteAce DeleteService
DeregisterEventSource DestroyPrivateObjectSecurity DuplicateTokenEx EncryptFileA EncryptFileW
EnumDependentServicesA EnumDependentServicesW EnumServicesStatusA EnumServicesStatusW
EqualDomainSid EqualPrefixSid EqualSid FindFirstFreeAce FreeSid GetAce GetAclInformation
GetAuditedPermissionsFromSidA GetAuditedPermissionsFromSidW GetCurrentHwProfileA
GetCurrentHwProfileW GetEffectiveRightsFromSidA GetEffectiveRightsFromSidW GetExplicitEntriesFromAclA
GetExplicitEntriesFromAclW GetFileSecurityA GetFileSecurityW GetKernelObjectSecurity
GetLengthSid GetLocalComputerName? GetNamedSecurityInfoA GetNamedSecurityInfoW
GetNumberOfEventLogRecords GetOldestEventLogRecord GetPrivateObjectSecurity GetSecurityDescriptorControl
GetSecurityDescriptorDacl GetSecurityDescriptorGroup GetSecurityDescriptorLength
GetSecurityDescriptorOwner GetSecurityDescriptorRMControl GetSecurityDescriptorSacl GetServiceDisplayNameA
GetServiceDisplayNameW GetServiceKeyNameA GetServiceKeyNameW GetSidIdentifierAuthority
GetSidLengthRequired GetSidSubAuthority GetSidSubAuthorityCount GetTokenInformation
GetTrusteeNameA GetTrusteeNameW GetTrusteeTypeA GetTrusteeTypeW GetUserObjectSecurity
GetWindowsAccountDomainSid ImpersonateLoggedOnUser ImpersonateNamedPipeClient
ImpersonateSelf InitiateSystemShutdownA InitiateSystemShutdownExA InitiateSystemShutdownExW
InitiateSystemShutdownW InitializeAcl InitializeSecurityDescriptor InitializeSid
IsTextUnicode IsValidAcl IsValidSecurityDescriptor IsValidSid LockServiceDatabase
LogonUserA LogonUserW LookupAccountNameA LookupAccountNameW LookupAccountSidA LookupAccountSidW
LookupPrivilegeDisplayNameA LookupPrivilegeDisplayNameW LookupPrivilegeNameA
LookupPrivilegeNameW LookupPrivilegeValueA LookupPrivilegeValueW LookupAccountDomainA?
MakeAbsoluteSD MakeSelfRelativeSD NotifyChangeEventLog ObjectCloseAuditAlarmA
ObjectCloseAuditAlarmW ObjectOpenAuditAlarmA ObjectOpenAuditAlarmW ObjectPrivilegeAuditAlarmA
ObjectPrivilegeAuditAlarmW OpenBackupEventLogA OpenBackupEventLogW OpenEncryptedFileRawA
OpenEncryptedFileRawW OpenEventLogA OpenEventLogW OpenProcessToken OpenSCManagerA OpenSCManagerW
OpenServiceA OpenServiceW OpenThreadToken PrivilegeCheck PrivilegedServiceAuditAlarmA
PrivilegedServiceAuditAlarmW QueryServiceConfigA QueryServiceConfigW QueryServiceLockStatusA
QueryServiceLockStatusW QueryServiceObjectSecurity QueryServiceStatus QueryServiceStatusEx
ReadEncryptedFileRaw RegCloseKey RegConnectRegistryA RegConnectRegistryW RegCreateKeyA
RegCreateKeyExA RegCreateKeyExW RegCreateKeyW RegDeleteKeyA RegDeleteKeyExA RegDeleteKeyExW
RegDeleteKeyW RegDeleteTreeA? RegDeleteValueA RegDeleteValueW RegDisablePredefinedCache?
RegEnumKeyA RegEnumKeyExA RegEnumKeyExW RegEnumKeyW RegEnumValueA RegEnumValueW
RegFlushKey RegGetKeySecurity RegLoadKeyA RegLoadKeyW RegNotifyChangeKeyValue
RegOpenCurrentUser RegOpenKeyA RegOpenKeyExA RegOpenKeyExW RegOpenKeyW RegOpenUserClassesRoot
RegOverridePredefKey RegQueryInfoKeyA RegQueryInfoKeyW RegQueryMultipleValuesA
RegQueryMultipleValuesW RegQueryValueA RegQueryValueExA RegQueryValueExW RegQueryValueW
RegReplaceKeyA RegReplaceKeyW RegRestoreKeyA RegRestoreKeyW RegSaveKeyA RegSaveKeyW
RegSetKeySecurity RegSetValueA RegSetValueExA RegSetValueExW RegSetValueW
RegUnLoadKeyA RegUnLoadKeyW RegisterEventSourceA RegisterEventSourceW RegisterServiceCtrlHandlerA
RegisterServiceCtrlHandlerExA RegisterServiceCtrlHandlerExW RegisterServiceCtrlHandlerW
ReportEventA ReportEventW RevertToSelf SetAclInformation SetEntriesInAclA SetEntriesInAclW
SetFileSecurityA SetFileSecurityW SetKernelObjectSecurity SetNamedSecurityInfoA
SetNamedSecurityInfoW SetPrivateObjectSecurity SetSecurityDescriptorControl
SetSecurityDescriptorDacl SetSecurityDescriptorGroup SetSecurityDescriptorOwner
SetSecurityDescriptorRMControl SetSecurityDescriptorSacl SetServiceObjectSecurity
SetServiceStatus SetThreadToken SetTokenInformation SetUserObjectSecurity
StartServiceA StartServiceA? StartServiceControlDispatcherA StartServiceControlDispatcherW
StartServiceW UnlockServiceDatabase WriteEncryptedFileRaw"""
SHL_EXTRA = """PathAppendA PathAppendW PathCanonicalizeA PathCanonicalizeW PathCombineA PathCombineW
PathCommonPrefixA PathCommonPrefixW PathFileExistsA PathFileExistsW PathFindExtensionA
PathFindExtensionW PathFindFileNameA PathFindFileNameW PathFindNextComponentA
PathFindNextComponentW PathGetArgsA PathGetArgsW PathGetDriveNumberA PathGetDriveNumberW
PathIsDirectoryA PathIsDirectoryEmptyA PathIsDirectoryEmptyW PathIsDirectoryW PathIsFileSpecA
PathIsFileSpecW PathIsRelativeA PathIsRelativeW PathIsRootA PathIsRootW PathIsSameRootA
PathIsSameRootW PathIsUNC A PathIsUNCA PathIsUNCServerA PathIsUNCServerShareA PathIsURLA
PathIsURLW PathMatchSpecA PathMatchSpecW PathRemoveBackslashA PathRemoveBackslashW
PathRemoveExtensionA PathRemoveExtensionW PathRemoveFileSpecA PathRemoveFileSpecW
PathRenameExtensionA PathRenameExtensionW PathSkipRootA PathSkipRootW PathStripPathA
PathStripPathW PathStripToRootA PathStripToRootW PathUnquoteSpacesA PathUnquoteSpacesW
PathQuoteSpacesA PathQuoteSpacesW PathAddBackslashA PathAddBackslashW
SHGetFileInfoA SHGetFileInfoW SHGetFolderPathA SHGetFolderPathW SHGetMalloc SHGetPathFromIDListA
SHGetPathFromIDListW SHGetSpecialFolderLocation SHGetSpecialFolderPathA SHGetSpecialFolderPathW
SHBrowseForFolderA SHBrowseForFolderW SHChangeNotify ShellExecuteA ShellExecuteW
ShellExecuteExA ShellExecuteExW Shell_NotifyIconA Shell_NotifyIconW ExtractIconA ExtractIconW
ExtractIconExA ExtractIconExW CommandLineToArgvW DragQueryFileA DragQueryFileW
FindExecutableA FindExecutableW ShellAboutA ShellAboutW SHAppBarMessage
SHCreateDirectoryExA SHCreateDirectoryExW SHFileOperationA SHFileOperationW
SHFreeNameMappings SHGetDesktopFolder SHGetInstanceExplorer SHGetFileVersionInfoA?
SHLoadInProc? SHQueryRecycleBinA SHQueryRecycleBinW SHEmptyRecycleBinA SHEmptyRecycleBinW
IsUserAnAdmin PathBuildRootA PathBuildRootW PathCreateFromUrlA PathCreateFromUrlW
PathYetAnotherMakeUniqueName AssocQueryStringA AssocQueryStringW StrFormatByteSizeA
StrFormatByteSizeW StrChrA StrChrW StrCmpNA StrCmpNW StrCmpNIA StrCmpNIW StrCpyNA StrCpyNW
StrDupA StrDupW StrFormatKBSizeA StrFormatKBSizeW StrIsEqual StrPBrkA StrPBrkW
StrRChrA StrRChrW StrRChrIA StrRChrIW StrRStrIA StrRStrIW StrSpnA StrSpnW StrStrA
StrStrIA StrStrIW StrStrW StrToIntA StrToIntExA StrToIntExW StrToIntW StrTrimA StrTrimW
SHDeleteKeyA SHDeleteKeyW SHGetValueA SHGetValueW SHSetValueA SHSetValueW
SHRegOpenUSKeyA SHRegQueryUSValueA wnsprintfA wnsprintfW wvnsprintfA wvnsprintfW
SHCreateStreamOnFileA SHCreateStreamOnFileW PathRelativePathToW UrlCanonicalizeA
UrlCombineA UrlUnescapeA UrlEscapeA"""

def build_fake_module(uc, dllname, names):
    base = MODS[dllname]
    names = sorted(set([n for n in names if n.isidentifier() or n.startswith('l')] +
                       [n.lower() for n in names]))
    N = len(names)
    # dynamic layout (no fixed offsets: offsets scale with N)
    funcs_rva  = 0x1200
    ords_rva   = funcs_rva + ((4*(N+1)+15) & ~15)
    names_rva  = ords_rva + ((2*(N+1)+15) & ~15)
    thunk_rva  = names_rva + ((4*(N+1)+15) & ~15)
    arena_rva  = thunk_rva + 16*(N+1)
    blob_base  = arena_rva + 0x40
    dname_rva  = blob_base + sum(len(n)+1 for n in names) + 0x40
    size = (dname_rva + 0x100 + 0xFFF) & ~0xFFF
    uc.mem_map(base, size)
    img = bytearray(size)
    # DOS header
    img[0:2] = b'MZ'; struct.pack_into('<I', img, 0x3C, 0x40)
    # PE header at 0x40
    peoff = 0x40
    img[peoff:peoff+4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', img, peoff+4, 0x14C, 1, 0, 0, 0, 0xE0, 0xF0)  # machine,nsec,ts,sym,nsym,optsz,chars
    # optional header
    o = peoff+24
    struct.pack_into('<H', img, o, 0x10B)                 # magic
    struct.pack_into('<I', img, o+28, base)               # ImageBase
    struct.pack_into('<I', img, o+56, size)               # SizeOfImage
    struct.pack_into('<I', img, o+96+0*8, 0x1000)         # DataDirectory[0] export RVA (96, not 92!)
    struct.pack_into('<I', img, o+96+0*8+4, 0x800)        # size
    # section header at peoff+24+0xE0
    s = peoff+24+0xE0
    img[s:s+8] = b'.exp\0\0\0\0'
    struct.pack_into('<IIII', img, s+8, 0x1000, 0x2000, 0x1000, 0x2000)  # vsize,vaddr,rawsize,rawaddr
    struct.pack_into('<I', img, s+36, 0x40000040)
    # export directory at RVA 0x1000; layout computed above
    name_rvas = []
    blob = bytearray()
    for n in names:
        name_rvas.append(blob_base + len(blob)); blob += n.encode() + b'\0'
    img[blob_base:blob_base+len(blob)] = blob
    _bait = b'LoadLibraryA\0'
    img[arena_rva:arena_rva+len(_bait)] = _bait          # arena slot 0
    e = 0x1000
    struct.pack_into('<II', img, e+0, 0, 0)
    struct.pack_into('<II', img, e+8, 0, 0)
    struct.pack_into('<I', img, e+12, dname_rva)         # Name RVA -> dll name string
    struct.pack_into('<I', img, e+16, 1)                 # ordinal base
    struct.pack_into('<I', img, e+20, N+1)               # NumberOfFunctions (incl arena slot)
    struct.pack_into('<I', img, e+24, N+1)               # NumberOfNames
    struct.pack_into('<I', img, e+28, funcs_rva)
    struct.pack_into('<I', img, e+32, names_rva)
    struct.pack_into('<I', img, e+36, ords_rva)
    dl = dllname.encode() + b'\0'
    img[dname_rva:dname_rva+len(dl)] = dl
    MOD_EXPORTS[dllname] = {n.lower(): (base, thunk_rva + 16*(i+1)) for i, n in enumerate(names)}
    all_names = ['LoadLibraryA'] + list(names)           # slot 0 = arena
    THUNK_NAMES[base] = {thunk_rva + 16*i: n for i, n in enumerate(all_names)}
    all_name_rvas = [arena_rva] + name_rvas
    for i, n in enumerate(all_names):
        t = thunk_rva + 16*i
        img[t:t+6] = b'\x68' + struct.pack('<I', get_stub(n) & 0xFFFFFFFF) + b'\xC3'
        struct.pack_into('<I', img, funcs_rva+4*i, t)
        struct.pack_into('<H', img, ords_rva+2*i, i)
        struct.pack_into('<I', img, names_rva+4*i, all_name_rvas[i])
    # register arena for the adaptive cmp hook
    ARENAS[base] = (base+arena_rva, base+arena_rva+0x40, base+thunk_rva)
    WALKS[base] = None
    uc.mem_write(base, bytes(img))

# ---------------- API shims ----------------
log = []
api_log = collections.Counter()
heap_ptr = [0x20000000]
valloc_ptr = [0x10000000]
dirty_pages = set()
write_events = []
OEP_HIT = [None]

def rd_str(uc, addr, wide=False, maxn=260):
    if not addr: return ''
    out = b''
    step = 2 if wide else 1
    for i in range(maxn):
        c = uc.mem_read(addr+i*step, step)
        if c == (b'\0\0' if wide else b'\0'): break
        out += c
    return out.decode('utf-16le' if wide else 'latin1', errors='replace')

# stdcall arg counts (for stack cleanup)
STDCALL_ARGS = {
 'getmodulehandlea':1,'loadlibrarya':1,'freelibrary':1,'getmodulefilenamew':3,'getmodulefilenamea':3,
 'getcurrentdirectoryw':2,'getcurrentdirectorya':2,'getuserdefaultuilanguage':0,'openthread':3,
 'openprocess':3,'allocateandinitializesid':11,'initializesecuritydescriptor':2,
 'setsecuritydescriptordacl':4,'setentriesinacla':6,'localalloc':2,'localfree':1,'virtualalloc':4,'virtualfree':3,
 'virtualprotect':4,'heapalloc':3,'heapfree':3,'getprocessheap':0,'getversionexa':1,
 'iswow64process2':3,'getcurrentthreadid':0,'getcommandlinea':0,
 # --- full manual-resolution set (stdcall arg counts) ---
 'loadlibraryw':1,'getprocaddress':2,'setevent':1,'setenvironmentvariablew':2,'setenvironmentvariablea':2,
 'waitforsingleobject':2,'createeventa':4,'createprocessw':10,'getstartuinfow':1,'getstartupinfow':1,
 'getthreadcontext':2,'getcurrentthread':0,'tlsalloc':0,'tlssetvalue':2,'tlsgetvalue':1,'freelibrary':1,
 'getenvironmentvariablea':3,'getenvironmentvariablew':3,'gettemppathw':2,'gettempfilenamew':4,
 'getuserdefaultuilanguage':0,'getversion':0,'getfilesize':2,'createfilea':7,'createfilew':7,
 'createfilemappingw':6,'mapviewoffile':5,'unmapviewoffile':1,'exitprocess':1,'regopenkeyw':3,
 'closehandle':1,'sleep':1,'rtlentercriticalsection':1,'rtlleavecriticalsection':1,
 'rtlinitializecriticalsection':1,'createthread':6,'ntqueryobject':5,'createlirectoryw':2,
 'regclosekey':1,'regflushkey':1,'regsetvalueexa':6,'regsetvalueexw':6,'outputdebugstringa':1,
 'isbadreadptr':2,'isbadwriteptr':2,'getfiletime':4,'setfiletime':4,'getshortpathnamew':3,
 'getlongpathnamew':3,'getwindowsdirectoryw':2,'getsystemdirectoryw':2,'messageboxexa':5,
 'messageboxexw':5,'getmodulehandlew':1,'virtualquery':3,'createtoolhelp32snapshot':2,
 'process32first':2,'process32next':2,'process32firstw':2,'process32nextw':2,'thread32first':2,
 'thread32next':2,'getcommandlinew':0,'terminatethread':2,'rtlreallocateheap':4,'rtlfreeheap':3,
 'widechartomultibyte':8,'multibytetowidechar':6,'charlowerw':1,'suspendthread':1,
 'setcurrentdirectoryw':1,'getfullpathnamew':4,'getfileattributesexw':4,'getfileattributesw':1,
 'getcurrentprocess':0,'getcurrentprocessid':0,'setfilepointer':4,'readfile':5,'writefile':5,
 'shgetspecialfolderpathw':4,'pathcanonicalizew':3,'copyfilew':3,'getprivateprofilestringw':8,
 'getprivateprofileintw':4,'getprivateprofilesectionw':4,'deletefilew':1,'lstrcpyna':3,'lstrcmpia':2,
 'strtointa':1,'regcreatekeyexa':7,'regcreatekeya':3,'regcreatekeyexw':7,'regopenkeya':3,
 'regqueryvalueexa':6,'regqueryvalueexw':6,'regdeletevaluea':2,'regdeletevaluew':2,'regenumkeyexa':8,
 'regqueryinfokeya':12,'regqueryinfokeyw':12,'getlocaltime':1,'getsystemtime':1,
 'systemtimetofiletime':2,'filetimetosystemtime':2,'iswow64process':2,'deviceiocontrol':8,
 'getmessagea':4,'translatemessage':1,'dispatchmessagea':1,'setentriesinacla':6,'localalloc':2,
 'initializesecuritydescriptor':2,'setsecuritydescriptordacl':4,'ntqueryperformancecounter':2,
 'reggetkeysecurity':3,'regopenuserclassesroot':4,'sleepconditionvariablecs':3,
 'closeprivatenamespace':2,'unregisterapplicationrecoverycallback':0,'regconnectregistrya':3,
 'loadmodule':3,'freelibraryandexitthread':2,'geteranamecountedstring':3,'getthreaderrormode':0,
 'getstdhandle':1,'waitforsingleobjectex':3,'createeventexa':4,'createremotethread':7,
'messageboxa':4,'immsetcompositionwindow':2,
 'imagelist_enddrag':0,'regqueryvalueexw':6,'netwkstagetinfo':4,'shgetfolderpathw':5,
 'verqueryvaluea':4,'shellexecuteexa':1,'charnextw':1,'sndplaysoundw':2,'openprinterw':3,
 'printdlgw':1,'oleuiobjectpropertiesw':1,'createilockbytesonhglobal':3,'sysfreestring':1,
 'pathrelativepathtow':5,'__wsafdisset':2,'initializeflatsb':1,'widenpath':0,'memset':3,
 'imagedirectoryentrytodata':4,'sleep':1,'exitprocess':1,'terminateprocess':2,'openprocess':3,
 'createprocessa':10,'getprocaddress':2,'isdebuggerpresent':0,'gettickcount':0,
 'queryperformancecounter':1,'ntqueryinformationprocess':5,'closehandle':1,
 'getcurrentprocess':0,'getcurrentprocessid':0,'virtualquery':3,'iswow64process':2,
 'outputdebugstringa':1,'getmodulefilenamea':3,'tlsgetvalue':1,'tlssetvalue':2,
 'ntsetinformationthread':4,'ntquerysysteminformation':4,'ntclose':1,
 'rtlallocateheap':3,'rtlfreeheap':3,'ldrloaddll':4,'ldrgetprocedureaddress':3,
 'ntallocatevirtualmemory':6,'ntfreevirtualmemory':4,'ntprotectvirtualmemory':5,
 'getsysteminfo':1,'globalmemorystatus':1,'seterrormode':1,'getstartupid':2,
}

def do_api(uc, name):
    esp = uc.reg_read(UC_X86_REG_ESP)
    def arg(i):
        return struct.unpack('<I', uc.mem_read(esp+4+4*i, 4))[0]
    n = name.lower(); api_log[n] += 1
    ret = 0
    if n == 'loadlibrarya' or n == 'getmodulehandlea':
        nm = rd_str(uc, arg(0)) if arg(0) else ''
        if api_log[n] <= 20: log.append(f'[{n}] "{nm}"')
        if api_log[n] <= 20:
            words = struct.unpack('<8I', uc.mem_read(esp-8, 32))
            log.append(f'[{n}] argptr={arg(0):#x} stack[esp-8..esp+24]={" ".join(hex(w) for w in words)}')
        if nm.lower() in MODS: ret = MODS[nm.lower()]
        elif nm == '': ret = IMAGE_BASE
        else:
            log.append(f'[{n}] unknown module "{nm}"')
            ret = 0
    elif n == 'virtualalloc':
        size = arg(1) or 0x1000
        a = (valloc_ptr[0] + 0xFFF) & ~0xFFF
        need_end = a + ((size+0xFFF)&~0xFFF)
        try: uc.mem_map(a, ((size+0xFFF)&~0xFFF))
        except UcError: pass
        valloc_ptr[0] = need_end
        ret = a
    elif n in ('virtualfree',):
        ret = 1
    elif n == 'virtualprotect':
        if arg(3): 
            try: uc.mem_write(arg(3), b'\x40')
            except UcError: pass
        ret = 1
    elif n in ('heapalloc','rtlallocateheap'):
        size = arg(2) if n=='heapalloc' else arg(2)
        a = (heap_ptr[0]+0xF) & ~0xF
        heap_ptr[0] = a + max(size,0x10)
        if heap_ptr[0] > 0x20800000: heap_ptr[0] = 0x20000000
        ret = a
    elif n in ('heapfree','rtlfreeheap'):
        ret = 1
    elif n == 'getprocessheap' or n == 'rtlallocateheap':
        ret = 0xCAFE0000 if n=='getprocessheap' else 0
    elif n == 'getversionexa':
        p = arg(0); sz = struct.unpack('<I', uc.mem_read(p,4))[0]
        uc.mem_write(p, struct.pack('<IIIII', sz, 10, 0, 19045, 2))
        uc.mem_write(p+20, b'Service Pack 0\0')
        ret = 1
    elif n == 'getcommandlinea':
        ret = CMDLINE_PTR[0]
    elif n == 'messageboxa':
        log.append(f'[MessageBoxA] "{rd_str(uc, arg(1))}" / "{rd_str(uc, arg(2))}"')
        ret = 1
    elif n == 'getmodulefilenamew':
        buf = arg(1)
        path = 'C:\\Test2.exe'
        try:
            uc.mem_write(buf, path.encode('utf-16le') + b'\0\0')
            ret = len(path)
        except UcError: ret = 0
    elif n == 'getmodulefilenamea':
        buf = arg(1)
        path = 'C:\\Test2.exe'
        try:
            uc.mem_write(buf, path.encode() + b'\0')
            ret = len(path)
        except UcError: ret = 0
    elif n == 'getcurrentdirectoryw':
        buf = arg(1)
        try:
            uc.mem_write(buf, 'C:\\'.encode('utf-16le') + b'\0\0')
            ret = 3
        except UcError: ret = 0
    elif n == 'getcurrentdirectorya':
        buf = arg(1)
        try:
            uc.mem_write(buf, b'C:\\\0')
            ret = 3
        except UcError: ret = 0
    elif n == 'iswow64process2':
        for p in (arg(1), arg(2)):
            if p:
                try: uc.mem_write(p, struct.pack('<HH', 0, 0x8664))  # WOW64_NONE / x64 host
                except UcError: pass
        ret = 1
    elif n in ('setenvironmentvariablew', 'setenvironmentvariablea'):
        ret = 1
    elif n == 'iswow64process':
        p = arg(1)
        if p:
            try: uc.mem_write(p, struct.pack('<I', 0))
            except UcError: pass
        ret = 1
    elif n == 'getuserdefaultuilanguage':
        ret = 0x409        # en-US
    elif n in ('openthread', 'openprocess'):
        FAKEHANDLE[0] += 4
        ret = 0x70000000 | FAKEHANDLE[0]
    elif n in ('allocateandinitializesid', 'initializesecuritydescriptor',
               'setsecuritydescriptordacl', 'setentriesinacla', 'setserviceobjectsecurity'):
        ret = 1 if not n.endswith('a') or n == 'setentriesinacla' else 1
    elif n == 'localalloc':
        a = (heap_ptr[0]+0xF) & ~0xF
        heap_ptr[0] = a + max(arg(1), 0x20)
        ret = a
    elif n == 'localfree':
        ret = 0
    elif n == 'setlasterror':
        LAST_ERROR[0] = arg(0); ret = 0
    elif n == 'getlasterror':
        ret = LAST_ERROR[0]
    elif n == 'gettickcount': ret = 0x1A2B3C4D
    elif n == 'queryperformancecounter':
        uc.mem_write(arg(0), struct.pack('<Q', 0x1122334455667788)); ret = 1
    elif n == 'getcurrentthreadid': ret = 0x53A
    elif n == 'getcurrentprocessid': ret = 0x539
    elif n == 'getcurrentprocess': ret = 0xFFFFFFFF
    elif n == 'isdebuggerpresent': ret = 0
    elif n == 'ntqueryinformationprocess': ret = 0xC0000004  # STATUS_INFO_LENGTH_MISMATCH-ish
    elif n == 'getprocaddress':
        a1 = arg(1)
        nm = None
        if 0x10000 < a1 < 0xFFFFFFF0:
            try:
                b = bytes(uc.mem_read(a1, 2))
                if all(32 <= c < 127 for c in b):   # printable -> it's a name string
                    nm = rd_str(uc, a1)
            except UcError:
                pass
        if nm is None:
            nm = f'ord{a1 & 0xFFFF}'
        log.append(f'[GetProcAddress] "{nm}"')
        ret = get_stub(nm)
        # prefer in-module thunk (address must lie inside the module: anti-hook check)
        hmod = arg(0)
        for dll, exp in MOD_EXPORTS.items():
            b = MODS[dll]
            if (hmod == 0 or hmod == b) and nm.lower() in exp:
                mb, trva = exp[nm.lower()]
                ret = mb + trva
                break
    elif n == 'memset':
        dst, c, cnt = arg(0), arg(1), arg(2)
        if cnt < 0x100000:
            try: uc.mem_write(dst, bytes([c & 0xFF])*cnt)
            except UcError: log.append(f'[memset] bad dst {dst:#x}')
        ret = dst
    elif n == 'imagedirectoryentrytodata':
        base, _, _, psize = arg(0), arg(1), arg(2), arg(3)
        dll = next((d for d,b in MODS.items() if b == base), None)
        if dll:
            uc.mem_write(psize, struct.pack('<I', 0x800))
            ret = base + 0x1000
        else:
            ret = 0
    elif n in ('regqueryvalueexw',):
        log.append(f'[RegQueryValueExW] type={arg(1)&0xF}')
        ret = 2
    elif n == 'netwkstagetinfo':
        ret = 1168
    elif n == 'shgetfolderpathw':
        buf = arg(3) if arg(3) else arg(4)
        try: uc.mem_write(buf, 'C:\\Users\\Public'.encode('utf-16le')+b'\0\0')
        except UcError: pass
        ret = 0
    elif n == 'sleep': ret = 0
    elif n == 'exitprocess' or n == 'terminateprocess':
        log.append(f'[{n}] code={arg(0):#x}')
        EXIT_FLAG[0] = True
        ret = 0
    elif n in ('wsprintfa', 'wsprintfw'):
        dst = arg(0); fmt = arg(1)
        try:
            f = rd_str(uc, fmt, wide=not n.endswith('a'))
            out = f  # identity format (no args parsed) - placeholder
            data = out.encode('latin1') if n.endswith('a') else out.encode('utf-16le')
            uc.mem_write(dst, data + (b'\0' if n.endswith('a') else b'\0\0'))
            ret = len(out)
        except Exception:
            ret = 0
    elif n == 'charnextw': ret = arg(0)+2
    elif n == 'virtualquery':
        ret = 0
    else:
        if api_log[n] <= 2: log.append(f'[api] {name}(args {[hex(arg(i)) for i in range(min(3, STDCALL_ARGS.get(n,1)))]}) -> default 0')
    nargs = STDCALL_ARGS.get(n)
    if nargs is None:
        nargs = 1
    if n in ('memset', 'wsprintfa', 'wsprintfw', 'wvsprintfa', 'wvsprintfw'):  # cdecl: caller cleans
        uc.reg_write(UC_X86_REG_EAX, ret)
        return
    # stdcall: emulate `ret imm16` here (skip stub's ret):
    # [esp]=retaddr, [esp+4..]=args -> EIP=retaddr, ESP=esp+4+4*nargs
    try:
        retaddr = struct.unpack('<I', uc.mem_read(esp, 4))[0]
    except UcError:
        return
    uc.reg_write(UC_X86_REG_EAX, ret)
    uc.reg_write(UC_X86_REG_ESP, esp + 4 + 4*nargs)
    uc.reg_write(UC_X86_REG_EIP, retaddr)

CMDLINE_PTR = [0]
LAST_ERROR = [0]
FAKEHANDLE = [0]
EXIT_FLAG = [False]

# ---------------- build the machine ----------------
uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(0, 0x1000)             # null page (fake-TEB pointers + SEH sentinel)
t_null = bytearray(0x1000)
struct.pack_into('<I', t_null, 0x00, 0xFFFFFFFF)   # fs:[0] SEH chain end
uc.mem_map(0x20000, 0x60000-0x20000)   # GDT area
uc.mem_map(0x200000, 0x200000)    # stack (2 MB)
uc.mem_map(0x20000000, 0x00800000) # heap (8 MB)
uc.mem_map(IMAGE_BASE, (SIZE_OF_IMAGE + 0xFFF) & ~0xFFF)

# image: headers + sections (raw -> rva)
data = open(PE_PATH,'rb').read()
uc.mem_write(IMAGE_BASE, data[:0x600])
for s in pe.sections:
    if s.SizeOfRawData:
        uc.mem_write(IMAGE_BASE + s.VirtualAddress, data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData])
# .winlice = pre-unpacked kernel
uc.mem_write(IMAGE_BASE + 0x18A7000, KERNEL)

# command line
uc.mem_map(0x7E000000, 0x1000)
uc.mem_write(0x7E000000, b'"Test2.exe"\0')
CMDLINE_PTR[0] = 0x7E000000

# stub page: fill with ret
uc.mem_map(STUB_PAGE, STUB_LIMIT-STUB_PAGE)
uc.mem_write(STUB_PAGE, b'\xC3' * (STUB_LIMIT-STUB_PAGE))

# GDT + FS -> TEB
GDT = 0x50000
def seg(base, limit, access, flags):
    return struct.pack('<I', (base & 0xFFFFFF) | ((base>>24)<<24) if False else 0)  # placeholder
def make_desc(base, limit, access, flags):
    b0 = base & 0xFFFFFF
    l0 = limit & 0xFFFF
    l1 = (limit >> 16) & 0xF
    return struct.pack('<IHB', b0 | (l0 << 32) if False else 0, 0, 0)  # replaced below
def desc(base, limit, acc, flg):
    # classic 8-byte GDT entry
    return struct.pack('<BBHBBH',
        base & 0xFF, (base>>8)&0xFF, limit & 0xFFFF,
        ((base>>16)&0xFF) | ((flg & 0x0F) << 8) if False else 0, 0, 0)
# build 8-byte descriptors properly:
def gdt_entry(base, limit, access, flags):
    return struct.pack('<II',
        (base & 0x00FFFFFF) | ((limit & 0xFFFF) << 32) if False else 0, 0)
# (do it manually - avoid clever packing errors)
def G(base, limit, access, flags):
    b = base & 0xFFFFFFFF; l = limit & 0xFFFFF
    word0 = (l & 0xFFFF) | ((b & 0xFFFF) << 16)
    word1 = ((access & 0xFF) | ((((l >> 16) & 0xF) | ((flags & 0xF) << 4)) << 8)
             | (((b >> 16) & 0xFF) << 16) | (((b >> 24) & 0xFF) << 24))
    return struct.pack('<II', word0, word1)
# GDT/boot-stub removed: unicorn raises #GP on ALL far transfers regardless (verified empirically);
# far control flow is emulated flat in hook_intr instead. FS base stays 0 -> fs:[X] reads linear X,
# so a fake TEB lives in the null page (see below).

# TEB / PEB
TEB, PEB = 0x7FFDE000, 0x7FFDF000
uc.mem_map(TEB, 0x1000); uc.mem_map(PEB, 0x1000)
uc.mem_write(0, bytes(t_null))
# FS base is 0 -> fs:[X] == linear [X]: fake TEB pointers inside null page
struct.pack_into('<I', t_null, 0x18, TEB)      # fs:[0x18] -> TEB self
struct.pack_into('<I', t_null, 0x30, PEB)      # fs:[0x30] -> PEB
# t_null[0]=0xFFFFFFFF sentinel (SEH chain end) already set
t = bytearray(0x1000)
struct.pack_into('<I', t, 0x00, 0xFFFFFFFF)
struct.pack_into('<I', t, 0x04, 0x400000)      # StackBase
struct.pack_into('<I', t, 0x08, 0x200000)      # StackLimit
struct.pack_into('<I', t, 0x18, TEB)
struct.pack_into('<II', t, 0x20, 0x539, 0x53A) # PID, TID
struct.pack_into('<I', t, 0x30, PEB)
struct.pack_into('<I', t, 0x34, 0)             # affinity
uc.mem_write(TEB, bytes(t))
p = bytearray(0x1000)
struct.pack_into('<B', p, 0x02, 0)             # BeingDebugged
struct.pack_into('<I', p, 0x08, IMAGE_BASE)
struct.pack_into('<I', p, 0x68, 0)             # NtGlobalFlag
uc.mem_write(PEB, bytes(p))

# fake modules with rich export lists
K32 = ['LoadLibraryA','GetProcAddress','GetModuleHandleA','VirtualAlloc','VirtualFree','VirtualProtect',
 'VirtualQuery','HeapAlloc','HeapFree','GetProcessHeap','GetVersionExA','GetCurrentThreadId','GetCommandLineA',
 'FreeLibrary','Sleep','ExitProcess','TerminateProcess','OpenProcess','CreateProcessA','IsDebuggerPresent',
 'GetTickCount','QueryPerformanceCounter','GetSystemInfo','GlobalMemoryStatus','CloseHandle','GetCurrentProcess',
 'GetCurrentProcessId','GetModuleFileNameA','GetModuleFileNameW','TlsGetValue','TlsSetValue','TlsAlloc','TlsFree',
 'OutputDebugStringA','SetErrorMode','CreateFileA','CreateFileW','ReadFile','WriteFile','SetFilePointer',
 'GetFileSize','GetSystemDirectoryA','GetWindowsDirectoryA','ExpandEnvironmentStringsA','ExpandEnvironmentStringsW',
 'GetEnvironmentVariableA','GetEnvironmentVariableW','MultiByteToWideChar','WideCharToMultiByte','lstrlenA','lstrlenW',
 'lstrcpyA','lstrcpynA','lstrcatA','CreateThread','ExitThread','WaitForSingleObject','GetExitCodeProcess',
 'InterlockedIncrement','InterlockedDecrement','IsWow64Process','GetStartUpInfoA','GetStartUpInfoW','LoadLibraryExA',
 'GetModuleHandleExA','GetLogicalDrives','GetDriveTypeA','FlushInstructionCache','GetDateFormatA','GetTimeFormatA',
 'GetLocalTime','GetSystemTime','SetUnhandledExceptionFilter','UnhandledExceptionFilter','RaiseException',
 'GetLastError','SetLastError','LocalAlloc','LocalFree','GlobalAlloc','GlobalFree','EnterCriticalSection',
 'LeaveCriticalSection','InitializeCriticalSection','DeleteCriticalSection','WaitForSingleObjectEx',
 'GetProcessVersion','GetPriorityClass','ReadProcessMemory','WriteProcessMemory','CreateRemoteThread',
 'SuspendThread','ResumeThread','GetThreadContext','SetThreadContext','DebugBreak','ContinueDebugEvent',
 'WaitForDebugEvent','IsProcessorFeaturePresent','IsValidCodePtr','RtlUnwind','lstrcmpiA','lstrcmpA','GetStdHandle']
NT = ['NtQueryInformationProcess','NtSetInformationThread','NtQuerySystemInformation','NtQueryObject','NtClose',
 'NtAllocateVirtualMemory','NtFreeVirtualMemory','NtProtectVirtualMemory','NtQueryVirtualMemory','RtlAllocateHeap',
 'RtlFreeHeap','RtlInitUnicodeString','LdrLoadDll','LdrGetProcedureAddress','NtYieldExecution','DbgUiRemoteBreakin',
 'DbgBreakPoint','NtQueryPerformanceCounter','KiUserExceptionDispatcher','NtContinue','NtCreateFile','NtOpenFile',
 'NtReadFile','NtWriteFile','RtlImageNtHeader','RtlImageDirectoryEntryToData','NtSetDebugFilterState',
 'LdrGetDllHandle','RtlDecompressBuffer','RtlCompareMemory','NtOpenProcess','NtTerminateProcess','memcpy','memset',
 'NtCurrentTeb','RtlAddVectoredExceptionHandler','RtlRemoveVectoredExceptionHandler','NtQueryDirectoryFile']
U32 = ['MessageBoxA','MessageBoxW','FindWindowA','FindWindowW','EnumWindows','GetForegroundWindow','GetWindowTextA',
 'GetWindowTextW','ShowWindow','SetWindowsHookExA','SetWindowsHookExW','UnhookWindowsHookEx','GetKeyboardLayout',
 'LoadStringA','LoadStringW','CharNextW','CharLowerA','CharUpperA','GetClassNameA','GetWindowThreadProcessId',
 'PostMessageA','SendMessageA','BroadcastSystemMessageA','SystemParametersInfoA','GetSystemMetrics','ExitWindowsEx',
 'RegisterClassA','CreateWindowExA','DefWindowProcA','GetMessageA','DispatchMessageA','MessageBoxIndirectA']
ADV = ['RegOpenKeyExA','RegOpenKeyExW','RegQueryValueExA','RegQueryValueExW','RegCloseKey','RegCreateKeyExA',
 'RegCreateKeyExW','RegSetValueExA','RegSetValueExW','RegEnumKeyExA','RegEnumKeyExW','RegDeleteKeyA',
 'RegQueryInfoKeyA','RegConnectRegistryA','LookupPrivilegeValueA','AdjustTokenPrivileges','OpenProcessToken',
 'GetTokenInformation','CheckTokenMembership','InitiateSystemShutdownA']
OTHER = {
 'version.dll': ['VerQueryValueA','VerQueryValueW','GetFileVersionInfoA','GetFileVersionInfoSizeA','GetFileVersionInfoSizeW','GetFileVersionInfoW'],
 'shfolder.dll': ['SHGetFolderPathW','SHGetFolderPathA','SHGetSpecialFolderPathA','SHGetSpecialFolderPathW'],
 'shell32.dll': ['ShellExecuteExA','ShellExecuteExW','ShellExecuteA','ShellExecuteW','SHGetMalloc','CommandLineToArgvW'],
 'gdi32.dll': ['WidenPath','GetDeviceCaps','CreateDCA','DeleteDC','TextOutA','BitBlt'],
 'comctl32.dll': ['InitializeFlatSB','ImageList_EndDrag','ImageList_BeginDrag','InitCommonControls'],
 'imm32.dll': ['ImmSetCompositionWindow','ImmGetContext','ImmReleaseContext','ImmSetCompositionFontA'],
 'winmm.dll': ['sndPlaySoundW','sndPlaySoundA','PlaySoundA','PlaySoundW','timeGetTime'],
 'winspool.drv': ['OpenPrinterW','OpenPrinterA','ClosePrinter'],
 'comdlg32.dll': ['PrintDlgW','PrintDlgA','GetOpenFileNameA','GetSaveFileNameW'],
 'oledlg.dll': ['OleUIObjectPropertiesW'],
 'ole32.dll': ['CreateILockBytesOnHGlobal','CoInitialize','CoUninitialize','CoCreateInstance'],
 'oleaut32.dll': ['SysFreeString','SysAllocString','SysStringLen','VariantInit'],
 'shlwapi.dll': ['PathRelativePathToW','PathAppendA','PathRemoveFileSpecA','PathFindFileNameA'],
 'wsock32.dll': ['__WSAFDIsSet','select','WSAStartup','WSACleanup','socket','connect','send','recv','closesocket'],
 'netapi32.dll': ['NetWkstaGetInfo','NetApiBufferFree','NetUserGetInfo'],
 'msvcrt.dll': ['memset','memcpy','memmove','strcpy','strlen','strcmp','strncmp','_stricmp','strstr','sprintf','printf'],
 'imagehlp.dll': ['ImageDirectoryEntryToData','MapFileAndCheckSumA','MapFileAndCheckSumW','CheckSumMappedFile'],
}
build_fake_module(uc, 'kernel32.dll', K32 + list(K32_EXTRA))
build_fake_module(uc, 'ntdll.dll', NT + NT_EXTRA.split())
build_fake_module(uc, 'user32.dll', U32 + U32_EXTRA.split())
build_fake_module(uc, 'advapi32.dll', ADV + ADV_EXTRA.split())
import json as _json
_diag = {}
for d, b in MODS.items():
    try:
        _diag[d] = {
            '0x2840': bytes(uc.mem_read(b+0x2840, 32)).hex(' '),
            '0x2800': bytes(uc.mem_read(b+0x2800, 32)).hex(' '),
            'names1': hex(struct.unpack('<I', uc.mem_read(b+0x1604, 4))[0]),
            'thunk0': bytes(uc.mem_read(b+0x2000, 8)).hex(' '),
            'name_rva': hex(struct.unpack('<I', uc.mem_read(b+0x100C, 4))[0]),
        }
    except UcError as e:
        _diag[d] = str(e)
open('/tmp/emu_mod_diag.json','w').write(_json.dumps(_diag, indent=1))
print('mod diag written')
OTHER['shell32.dll'] = list(OTHER.get('shell32.dll', [])) + SHL_EXTRA.split()
OTHER['shlwapi.dll'] = list(OTHER.get('shlwapi.dll', [])) + SHL_EXTRA.split()
ADV_EXTRA = ADV_EXTRA.split() + open('/tmp/adv_win7_all.txt').read().split()
U32_EXTRA = U32_EXTRA.split() + open('/tmp/u32_win7_all.txt').read().split()
for dll, names in OTHER.items():
    build_fake_module(uc, dll, names)


# pre-fill the real IAT with stub addresses
iat_filled = 0
try:
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode().lower()
        for imp in entry.imports:
            nm = imp.name.decode() if imp.name else f'ord_{imp.ordinal}'
            uc.mem_write(imp.address, struct.pack('<I', get_stub(nm)))
            iat_filled += 1
except Exception as e:
    log.append(f'IAT fill error: {e}')
log.append(f'IAT pre-filled: {iat_filled} entries')

# ---------------- hooks ----------------
def hook_code_api(uc, addr, size, ud):
    name = addr_stub_of.get(addr)
    if name:
        do_api(uc, name)
def hook_code_oep(uc, addr, size, ud):
    OEP_HIT[0] = addr
    uc.emu_stop()
def hook_mem_invalid(uc, access, address, size, value, ud):
    kinds = {UC_MEM_READ_UNMAPPED:'R', UC_MEM_WRITE_UNMAPPED:'W', UC_MEM_FETCH_UNMAPPED:'X',
             UC_MEM_READ_PROT:'r', UC_MEM_WRITE_PROT:'w'}
    log.append(f'[MEM-FAULT {kinds.get(access,access)}] addr={address:#x} size={size} eip={uc.reg_read(UC_X86_REG_EIP):#x}')
    # auto-map plausible regions, else stop
    if 0x10000000 <= address < 0x60000000 or 0x02000000 <= address < 0x10000000 or address >= 0x7E000000:
        try:
            uc.mem_map(address & ~0xFFF, 0x1000); return True
        except UcError: return False
    return False
SEC0_LO, SEC10_HI = 0x401000, IMAGE_BASE+0x1890000
def hook_mem_write(uc, access, address, size, value, ud):
    if SEC0_LO <= address < SEC10_HI:
        dirty_pages.add(address & ~0xFFF)
        if len(write_events) < 400:
            write_events.append((uc.reg_read(UC_X86_REG_EIP), address, size, value))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
_md = Cs(CS_ARCH_X86, CS_MODE_32)
def insn_len_at(uc, eip):
    try:
        b = bytes(uc.mem_read(eip, 16))
        ins = next(_md.disasm(b, eip), None)
        return ins, (ins.size if ins else 2)
    except UcError:
        return None, 2
import collections
trace_ring = collections.deque(maxlen=700000)
LAND_DUMPED = [False]
def hook_trace(uc, addr, size, ud):
    trace_ring.append(addr)
    if addr == 0x30088b6 and not LAND_DUMPED[0]:
        LAND_DUMPED[0] = True
        try:
            blob = bytes(uc.mem_read(0x3008800, 0x100))
            open('/tmp/emu_land.bin','wb').write(blob)
            log.append(f'[LAND] bytes@0x3008800: {blob[0xb6-0x00:0xb6+0x10].hex()}')
            log.append(f'[LAND] esp={uc.reg_read(UC_X86_REG_ESP):#x} ebp={uc.reg_read(UC_X86_REG_EBP):#x} eax={uc.reg_read(UC_X86_REG_EAX):#x}')
            for nm, r in (('esp',UC_X86_REG_ESP),('ebp',UC_X86_REG_EBP),('esi',UC_X86_REG_ESI),('edi',UC_X86_REG_EDI)):
                v = uc.reg_read(r)
                try: log.append(f'[LAND] {nm}={v:#x} -> {bytes(uc.mem_read(v,16)).hex()}')
                except UcError: log.append(f'[LAND] {nm}={v:#x} <unmapped>')
        except UcError as e:
            log.append(f'[LAND] read fail {e}')
uc.hook_add(UC_HOOK_CODE, hook_trace)

def hook_intr(uc, intno, ud):
    eip = uc.reg_read(UC_X86_REG_EIP)
    esp = uc.reg_read(UC_X86_REG_ESP)
    ins, ln = insn_len_at(uc, eip)
    mn = ins.mnemonic if ins else '???'
    op = ins.op_str if ins else ''
    if intno in (1, 3, 0x2d):                       # anti-debug ints: skip
        uc.reg_write(UC_X86_REG_EIP, eip + ln); return
    if intno == 6:                                  # invalid opcode: skip
        if len(log) < 5000: log.append(f'[UD] eip={eip:#x} {mn} {op}')
        uc.reg_write(UC_X86_REG_EIP, eip + ln); return
    if intno == 0xd:                                # #GP: far transfer / privileged
        if mn == 'retf':
            new_eip, new_cs = struct.unpack('<II', uc.mem_read(esp, 8))
            imm = 0
            if op.strip():
                imm = int(op.split(',')[0].strip(), 0)
            uc.reg_write(UC_X86_REG_ESP, esp + 8 + imm)
            uc.reg_write(UC_X86_REG_EIP, new_eip)
            if len(log) < 5000: log.append(f'[retf emulated] eip={eip:#x} -> {new_eip:#x} cs={new_cs:#x}')
            return
        if mn in ('jmpf', 'ljmp'):
            # op like '0x08:0x7d00000e' or '8:0x7d00000e'
            try:
                sel_s, off_s = op.split(':')
                tgt = int(off_s, 0)
            except Exception:
                tgt = None
            if tgt is not None:
                uc.reg_write(UC_X86_REG_EIP, tgt)
                if len(log) < 5000: log.append(f'[ljmp flat] {eip:#x} -> {tgt:#x} sel={sel_s}')
                return
        if mn in ('callf', 'lcall'):
            try:
                sel_s, off_s = op.split(':')
                tgt = int(off_s, 0)
            except Exception:
                tgt = None
            if tgt is not None:
                uc.reg_write(UC_X86_REG_ESP, esp - 8)
                uc.mem_write(esp - 8, struct.pack('<II', 0, eip + ln))  # cs=0, ret eip
                uc.reg_write(UC_X86_REG_EIP, tgt)
                if len(log) < 5000: log.append(f'[lcall flat] {eip:#x} -> {tgt:#x} sel={sel_s}')
                return
        if mn in ('iret', 'iretd', 'iretq'):
            new_eip, new_cs, flg = struct.unpack('<III', uc.mem_read(esp, 12))
            uc.reg_write(UC_X86_REG_ESP, esp + 12)
            uc.reg_write(UC_X86_REG_EFLAGS, flg)
            uc.reg_write(UC_X86_REG_EIP, new_eip)
            if len(log) < 5000: log.append(f'[iretd flat] {eip:#x} -> {new_eip:#x} cs={new_cs:#x}')
            return
        # privileged/misc: skip instruction
        if len(log) < 5000: log.append(f'[GP skip] eip={eip:#x} {mn} {op}')
        uc.reg_write(UC_X86_REG_EIP, eip + ln); return
    if intno == 8:
        log.append(f'[DOUBLE FAULT] eip={eip:#x} {mn} {op}'); uc.emu_stop(); return
    if len(log) < 5000: log.append(f'[INT {intno:#x}] eip={eip:#x} {mn} {op}')
    uc.reg_write(UC_X86_REG_EIP, eip + ln)

uc.hook_add(UC_HOOK_CODE, hook_code_api, begin=STUB_PAGE, end=STUB_LIMIT-1)
uc.hook_add(UC_HOOK_CODE, hook_code_oep, begin=SEC0_LO, end=0x400000+0x1890000)  # original sections range
uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, begin=SEC0_LO, end=SEC10_HI-1)
uc.hook_add(UC_HOOK_INTR, hook_intr)
def hook_in(uc, port, size, ud):
    if len(log) < 5000 and port not in (0x80,): log.append(f'[IN port {port:#x} sz{size}] eip={uc.reg_read(UC_X86_REG_EIP):#x}')
    return 0xFFFFFFFF
def hook_out(uc, port, size, value, ud):
    if len(log) < 5000: log.append(f'[OUT port {port:#x} sz{size} = {value:#x}] eip={uc.reg_read(UC_X86_REG_EIP):#x}')
uc.hook_add(UC_HOOK_INSN, hook_in, None, 1, 0, UC_X86_INS_IN)
uc.hook_add(UC_HOOK_INSN, hook_out, None, 1, 0, UC_X86_INS_OUT)
kwrites = []
def hook_kwrite(uc, access, address, size, value, ud):
    if len(kwrites) < 3000:
        kwrites.append((address, size, value, uc.reg_read(UC_X86_REG_EIP)))
uc.hook_add(UC_HOOK_MEM_WRITE, hook_kwrite, None, 0x2F00000, 0x3060000)
kreads = []
CMPS = []
RESOLVED = []
CMPDBG = []
def hook_cmpsite(uc, addr, size, ud):
    al = uc.reg_read(UC_X86_REG_EAX) & 0xFF
    edi = uc.reg_read(UC_X86_REG_EDI)
    if len(CMPDBG) < 200000:
        CMPDBG.append((al, edi))
    for base, (alo, ahi, thunk0) in ARENAS.items():
        if alo <= edi < ahi:
            w = WALKS[base]
            if edi == alo or w is None:
                w = {}; WALKS[base] = w
            off = edi - alo
            w[off] = al
            uc.mem_write(edi, bytes([al & 0xFF]))
            if al == 0:
                s = ''.join(chr(w[i]) for i in range(max(w)+1) if w.get(i, 0) != 0 and 32 <= w[i] < 127)
                RESOLVED.append((base, s))
                if len(log) < 5000: log.append(f'[walk] {hex(base)} "{s}"')
                stub = get_stub(s)
                uc.mem_write(thunk0, b'\x68' + struct.pack('<I', stub & 0xFFFFFFFF) + b'\xC3')
                WALKS[base] = None
            break
uc.hook_add(UC_HOOK_CODE, hook_cmpsite, None, 0x1CA817A, 0x1CA817A)
SCANLOG = []
def hook_scan(uc, addr, size, ud):
    edx = uc.reg_read(UC_X86_REG_EDX)
    if 0x1F000000 <= edx < 0x22000000 and len(SCANLOG) < 60:
        SCANLOG.append((edx, uc.reg_read(UC_X86_REG_ECX) & 0xFFFF,
                        uc.reg_read(UC_X86_REG_EBP) & 0xFFFFFF, bytes(uc.mem_read(edx,8)) if edx < 0x20000000 else b'heap'))
uc.hook_add(UC_HOOK_CODE, hook_scan, None, 0x1CC65A1, 0x1CC65A1)
HASHLOG = []
_hashst = {'target': None, 'matched': False, 'names': 0}
def hook_hashcmp(uc, addr, size, ud):
    edx = uc.reg_read(UC_X86_REG_EDX); eax = uc.reg_read(UC_X86_REG_EAX)
    esi = uc.reg_read(UC_X86_REG_ESI)
    if eax != _hashst['target']:
        # new walk begins
        if _hashst['target'] is not None and not _hashst['matched']:
            HASHLOG.append(('FAILED', _hashst['target'], _hashst['names']))
        _hashst['target'] = eax; _hashst['matched'] = False; _hashst['names'] = 0
    _hashst['names'] += 1
    if edx == eax:
        try:
            nm = uc.mem_read(esi, 64).split(b'\0')[0].decode('latin1')
        except Exception:
            nm = '?'
        _hashst['matched'] = True
        HASHLOG.append(('MATCH', eax, nm))
uc.hook_add(UC_HOOK_CODE, hook_hashcmp, None, 0x2F8FC65, 0x2F8FC65)
HASHROWS = []
_pending = {'name': None}
def hook_strname(uc, addr, size, ud):
    ecx = uc.reg_read(UC_X86_REG_ECX); edx = uc.reg_read(UC_X86_REG_EDX)
    if ecx == 0xFFFFFFFF and edx == 0xFFFFFFFF:   # first byte of a name hash
        esi = uc.reg_read(UC_X86_REG_ESI)
        try:
            nm = uc.mem_read(esi, 48).split(b'\0')[0].decode('latin1')
        except Exception:
            nm = '?'
        _pending['name'] = nm
uc.hook_add(UC_HOOK_CODE, hook_strname, None, 0x307E4D5, 0x307E4D5)
def hook_hashrow(uc, addr, size, ud):
    ebp = uc.reg_read(UC_X86_REG_EBP)
    eax = uc.reg_read(UC_X86_REG_EAX); edx = uc.reg_read(UC_X86_REG_EDX)
    HASHROWS.append((_pending['name'], ebp, eax, edx))
uc.hook_add(UC_HOOK_CODE, hook_hashrow, None, 0x2F8FC65, 0x2F8FC65)
def hook_tblload(uc, addr, size, ud):
    edx = uc.reg_read(UC_X86_REG_EDX); ebp = uc.reg_read(UC_X86_REG_EBP)
    try:
        entry = int.from_bytes(uc.mem_read(edx, 4), 'little')
        tblbase = int.from_bytes(uc.mem_read(ebp+0x38, 4), 'little')
        idx = (edx - tblbase) >> 2
        around = b''.join(uc.mem_read(tblbase + 4*i, 4) for i in range(0, 260))
        ent = [int.from_bytes(around[4*i:4*i+4],'little') for i in range(260)]
        nz = [(i,v) for i,v in enumerate(ent) if v]
        bc = int.from_bytes(uc.mem_read(ebp+0x84, 4), 'little')
        log.append(f'[tbl] idx={idx} entry={entry:#x} table={tblbase:#x} bcptr={bc:#x} nonzero_entries={len(nz)}')
        log.append('[tbl] nonzero: ' + ' '.join(f'{i}:{v:#x}' for i,v in nz[:60]))
    except Exception as e:
        log.append(f'[tbl] err {e}')
uc.hook_add(UC_HOOK_CODE, hook_tblload, None, 0x2FED662, 0x2FED662)
def hook_thunk(uc, addr, size, ud):
    for base, tmap in THUNK_NAMES.items():
        nm = tmap.get(addr - base)
        if nm is not None:
            RESOLVED_LOG.append((base, nm, addr))
            if len(RESOLVED_LOG) < 400:
                log.append(f'[resolved] {nm} via {hex(base)} thunk')
            break
for base in MODS.values():
    uc.hook_add(UC_HOOK_CODE, hook_thunk, None, base, base+0x40000)
TARGET_DUMPED = [False]
def _ascii32(b):
    s = ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)
    return s
def hook_kread(uc, access, address, size, value, ud):
    if len(kreads) < 30000:
        kreads.append((address, size, uc.reg_read(UC_X86_REG_EIP)))
    if address == 0x77E02400 and not TARGET_DUMPED[0]:
        TARGET_DUMPED[0] = True
        for nm, r in (('eax',UC_X86_REG_EAX),('ebx',UC_X86_REG_EBX),('ecx',UC_X86_REG_ECX),
                      ('edx',UC_X86_REG_EDX),('esi',UC_X86_REG_ESI),('edi',UC_X86_REG_EDI),
                      ('ebp',UC_X86_REG_EBP),('esp',UC_X86_REG_ESP)):
            v = uc.reg_read(r)
            try:
                b = bytes(uc.mem_read(v, 48))
                log.append(f'[CMP] {nm}={v:#x}: {_ascii32(b)}')
            except UcError:
                log.append(f'[CMP] {nm}={v:#x} <unmapped>')
        try:
            for off in range(-16, 64, 8):
                w = struct.unpack('<I', uc.mem_read(uc.reg_read(UC_X86_REG_ESP)+off, 4))[0]
                try:
                    b = bytes(uc.mem_read(w, 32))
                    log.append(f'[CMP] [esp{off:+d}]={w:#x}: {_ascii32(b)}')
                except UcError:
                    log.append(f'[CMP] [esp{off:+d}]={w:#x}')
        except UcError: pass
for lo, hi in ((0x77C00000, 0x78000000), (0x7FFDE000, 0x7FFE0000), (0x7C9C0000, 0x7C9D0000)):
    uc.hook_add(UC_HOOK_MEM_READ, hook_kread, None, lo, hi)


import os
TRACE_ON = bool(os.environ.get('TRACE'))
TRACE = [0]
def hook_trace(uc, addr, size, ud):
    if not TRACE_ON: return
    if TRACE_ON and TRACE[0] < 400:
        TRACE[0] += 1
        try:
            b = bytes(uc.mem_read(addr, min(size, 12)))
        except UcError:
            b = b'?'
        esp = uc.reg_read(UC_X86_REG_ESP)
        try:
            stack = struct.unpack('<6I', uc.mem_read(esp, 24))
        except UcError:
            stack = ()
        print(f'T{TRACE[0]:03d} {addr:#x} sz={size} bytes={b.hex()} esp={esp:#x} stack={[hex(x) for x in stack]}', flush=True)
    if TRACE_ON and TRACE[0] >= 400:
        uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hook_trace)

# ---------------- run ----------------
ESP0 = 0x3F0000
uc.reg_write(UC_X86_REG_ESP, ESP0-0x100)
uc.mem_write(ESP0-0x104, struct.pack('<I', 0xDEAD0001))   # sentinel return addr
uc.reg_write(UC_X86_REG_EBP, ESP0-0x800)
uc.reg_write(UC_X86_REG_EAX, ENTRY)

CHUNK = 20_000_000
total = 0
t0 = time.time()
start_ip = ENTRY
status = 'budget'
try:
    while total < 2_000_000_000:
        if time.time() - t0 > 840: status='time'; break
        try:
            uc.emu_start(start_ip, 0xDEAD0001, count=CHUNK)
        except UcError as e:
            eip = uc.reg_read(UC_X86_REG_EIP)
            log.append(f'[UC-ERROR {e}] eip={eip:#x} after {total} insns')
            status = f'error:{e}'
            break
        if EXIT_FLAG[0]:
            status = 'exitprocess'; break
        eip = uc.reg_read(UC_X86_REG_EIP)
        if eip == 0xDEAD0001:
            status = 'completed-until'; break
        # count exhausted mid-run: resume from current EIP
        total += CHUNK
        start_ip = eip
        start_ip = uc.reg_read(UC_X86_REG_EIP)
        print(f'  ... {total/1e6:.0f}M insns, eip={start_ip:#x}, apis={sum(api_log.values())}, dirty_pages={len(dirty_pages)} ({time.time()-t0:.0f}s)', flush=True)
        if start_ip == 0xDEAD0001: status='returned-to-sentinel'; break
except Exception as e:
    status = f'pyerror:{e}'

print(f'=== status: {status} | insns ~{total} | {time.time()-t0:.0f}s ===')
print(f'=== OEP hit: {OEP_HIT[0]} ===')
print(f'=== dirty pages in encrypted sections: {len(dirty_pages)} ===')
print('=== API call census ===')
for k,v in api_log.most_common(40): print(f'  {v:6} {k}')
print('=== event log (first 120) ===')
for l in log[:120]: print('  '+l)
if write_events:
    print('=== first 30 writes into encrypted sections ===')
    for eip, addr, size, value in write_events[:30]:
        print(f'  eip={eip:#x} -> [{addr:#x}] size={size} value={value:#x}')
# dump dirty pages
import json
json.dump({'status':status,'oep':OEP_HIT[0],'dirty':[hex(p) for p in sorted(dirty_pages)],
           'apis':dict(api_log),'log':log[:2000]}, open('/tmp/emu_result.json','w'))
from capstone import Cs as _Cs, CS_ARCH_X86 as _AX, CS_MODE_32 as _M32
_md2 = _Cs(_AX, _M32)
rlines = []
for a in list(trace_ring)[-700000:]:
    try:
        b = bytes(uc.mem_read(a, 16))
        ins = next(_md2.disasm(b, a), None)
        rlines.append(f'{a:#010x}: {ins.mnemonic} {ins.op_str}' if ins else f'{a:#010x}: ??? {b[:8].hex()}')
    except UcError:
        rlines.append(f'{a:#010x}: <unmapped>')
open('/tmp/emu_ring.txt','w').write('\n'.join(rlines))
open('/tmp/emu_kwrites.txt','w').write('\n'.join(f'{a:#x} sz={s} val={v:#x} from_eip={e:#x}' for a,s,v,e in kwrites))
# walk analysis: group consecutive non-decreasing edi sweeps
MODBASES = sorted(MODS.items(), key=lambda kv: -kv[1])
def modof(a):
    for nm, b in MODBASES:
        if b <= a < b + 0x40000: return nm
    return None
walks = []
cur = []
for al, edi in CMPDBG:
    if cur and edi < cur[-1][1]:
        walks.append(cur); cur = []
    cur.append((al, edi))
if cur: walks.append(cur)
lines = []
for w in walks:
    if len(w) < 5: continue
    mod = modof(w[0][1])
    als = sorted(set(chr(a) if 32 <= a < 127 else f'x{a:02x}' for a, _ in w))
    # matched: edi increments within same string
    matched = any(w[i][1] == w[i-1][1] + 1 for i in range(1, len(w)))
    lines.append(f'{mod}: {len(w):4d} cmps  al={"/".join(als)}  deep={"Y" if matched else "n"}')
open('/tmp/emu_walks.txt','w').write('\n'.join(lines))
print(f'{len(walks)} walks -> /tmp/emu_walks.txt')
open('/tmp/emu_scan.txt','w').write('\n'.join(
    f'edx={d:#x} cx={c:#04x} ebp={b:#x} mem={m.hex() if isinstance(m,bytes) else m}' for d,c,b,m in SCANLOG))
open('/tmp/emu_hashrows.txt','w').write('\n'.join(f'{nm} {ebp:#x} {eax:#x} {edx:#x} {1 if eax==edx else 0}' for nm,ebp,eax,edx in HASHROWS))
open('/tmp/emu_hashlog.txt','w').write('\n'.join(f'{k} target={t:#x} {n}' for k,t,n in HASHLOG))
open('/tmp/emu_thunkres.txt','w').write('\n'.join(f'{hex(b)} {nm} @ {hex(a)}' for b,nm,a in RESOLVED_LOG))
open('/tmp/emu_resolved.txt','w').write('\n'.join(f'{hex(b)} {s}' for b, s in RESOLVED))
open('/tmp/emu_kreads.txt','w').write('\n'.join(f'{a:#x} sz={s} from_eip={e:#x}' for a,s,e in kreads))
open('/tmp/emu_cmps.txt','w').write('\n'.join(
    f'al={al:#04x} {chr(al) if 32<=al<127 else "."} edi={edi:#x} [edi]={m[:12]}' for al,edi,m in CMPS))
print(f'cmp-site hits: {len(CMPS)} -> /tmp/emu_cmps.txt')
print(f'kreads: {len(kreads)} -> /tmp/emu_kreads.txt')
print(f'ring: {len(trace_ring)} insns -> /tmp/emu_ring.txt; kwrites: {len(kwrites)} -> /tmp/emu_kwrites.txt')
if dirty_pages:
    with open('/tmp/emu_sec_dump.bin','wb') as f:
        for p in sorted(dirty_pages):
            try: f.write(uc.mem_read(p, 0x1000))
            except UcError: f.write(b'\0'*0x1000)
    print(f'dumped {len(dirty_pages)} dirty pages -> /tmp/emu_sec_dump.bin')
