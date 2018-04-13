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

public static class Kernel32_OpenProcess {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,  
        bool bInheritHandle,   
        uint dwProcessId      
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
        IntPtr hProcess,         // 
        IntPtr lpAddress,        // 
        uint dwSize,            // 
        uint flAllocationType,  // 
        uint flProtect          //
    );
}

public static class Kernel32_GetModuleHandle {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(
        byte[] lpModuleName   // 
    );
}

public static class Kernel32_GetProcAddress {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetProcAddress(
      IntPtr hModule,    //  
      byte[] lpProcName   // 
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

public static class Kernel32_GetLastError {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
        public static extern uint GetLastError(
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
        # Error Code reference: https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
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

        ### Get Procedure address of LoadLibraryA
        $aLoadLibraryA = Get-ProcAddress kernel32.dll LoadLibraryA
        Write-Verbose ("GetProcAddress() = " + ([Int64]$aLoadLibraryA).ToString("X0"))

        ### Prepare Fuction Arguments in Remote Process
        $MEM_COMMIT = 0x00001000
        $PAGE_READWRITE = 0x4
        $len = 128
        $writeLen = 0
        $baseAddr = [Kernel32_VirtualAllocEx]::VirtualAllocEx($hProcess, 0, $len, $MEM_COMMIT, $PAGE_READWRITE)
        Write-Verbose ("VirtualAllocEx() = " + ([Int64]$baseAddr).ToString("X0"))

        [byte[]]$dllPath = $utf8Enc.GetBytes("E:\TechBookFest\C93\spy.dll") # for 64 bit
        $res = [kernel32_WriteProcessMemory]::WriteProcessMemory($hProcess, $baseAddr, $dllPath, $len, [ref] $writeLen)
        if ($res -eq 0) {
            Throw "WriteProcessMemory failed"
        }

        Write-Host -NoNewLine 'Press any key to continue...';
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

        ### Call MessageBoxA in Remote Process
        $hThread = [Kernel32_CreateRemoteThread]::CreateRemoteThread(
            $hProcess, # Handle of Remote Process
            0, # Security Attributes
            0, # Initial Stack Size
            $aLoadLibraryA, # Start Address
            $baseAddr, # Function Parameters (Only ONE Parameter)
            0, # Creation Flags
            0 # lpTreadId
            )
        if ($hThread -eq 0) {
            Throw "MessageBoxA() failed"
        }
        Write-Verbose ("CreateRemoteThread() = " + ([Int64]$hThread).ToString("X0"))
        Get-LastError
  
    }

    $VerbosePreference = "Continue"
    Main
}

Invoke-Inject