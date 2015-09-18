GDIObjDump v1.0 - pnx!/CORE

What is this?:
--------------
    GDIObjDump is a debugger extension (WinDbg/Kd) to aid in the process of exploiting SessionPool overflows. 
    It can extract information for all GDI Objects listed in either PEB.GdiSharedHandleTable or WIN32K!gpentHmgr.
    GDIObjDump can output information in either text (console/logfile) or binary format (GDIObjView).
    
GDIObjView:
-----------
    GDIObjView is a stand alone application that displays binary output from GDIObjDump in a graphical way. 
    Instead of having to dig through thousands of lines of text, it displays the gdi table visually as a grid
    of cells, each cell representing a GDI object.
    
    It also allows the user to filter and/or sort the grid by object address, type, handle or pid.

Installation:
-------------
    To "install", copy gdiobjdump.dll to the winext folder for x64 WinDbg/Kd. 
    The path to the winext folder usually looks something like "<Program Files>Debugging Tools for Windows (x64)\winext"

    After that, you can issue "!load gdiobjdump" to load the extension into WinDbg/Kd. 
    
    NOTE: Only x64 Windbg/Kd is supported. Use the x64 debugger versions even for x86 targets.
        
Usage: 
------
    !gdiobjdump -[uk] -[ab][filename] -filter
    
    -u dumps PEB.GdiSharedHandleTable (default)
    -k dumps WIN32K!gpentHmgr
    -a [filename] - text output
    -b [filename] - binary output
    
    Filter options (matches only):
        -h <hex> specific handle
        -p <hex> specific pid
        -t <hex> specific type

Output:
-------
    If neither -b or -a switches are used, default output is printed on to debugger console.
    If -a switch is used, a filename is required and text output is written there.
    If -b switch is used, a filename is required and binary output is written there.

    examples: 
        !gdiobjdump -u                                          # - Parses PEB.GdiSharedHandleTable and outputs text to the debugger console.
        
        !gdiobjdump -k -b c:\temp\out.gdidump                   # - Parses WIN32K!gpentHmgr and writes binary output to "c:\temp\out.gdidump" 
        
        !gdiobjdump -a c:\temp\out.log -p 644 -t a -h 150a02dc  # - Parses PEB.GdiSharedHandleTable, outputs text to "c:\temp\out.log", 
                                                                #   log file will only include information about GDI objects matching 
                                                                #    Pid:0x644, Type:0x0a (GDIObjType_LFONT_TYPE), Handle:0x150a02dc
