// Copyright 2015 Core Security Technologies.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "stdafx.h"
#include <imagehlp.h>

#include <vector>
#include "GdiObjectLogger.h"


// Global Variable Needed For Functions
WINDBG_EXTENSION_APIS ExtensionApis = {0};
                      
// Global Variable Needed For Versioning
EXT_API_VERSION g_ExtApiVersion = {1 , 1 , EXT_API_VERSION_NUMBER , 0};
//EXT_API_VERSION g_ExtApiVersion = {0 , 0 , 0, 0};

// ExtensionApiVersion
LPEXT_API_VERSION WDBGAPI ExtensionApiVersion (void)
{
    return &g_ExtApiVersion;
}

// WinDbgExtensionDllInit
VOID WDBGAPI WinDbgExtensionDllInit (PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
     ExtensionApis = *lpExtensionApis;
}

// !help
DECLARE_API (help)
{
	dprintf("GDIObjDump v1.0 - pnx!/CORE\n");
	dprintf("Usage: \n\t!gdiobjdump -[uk] -[ab][filename] -filter\n\n");
	dprintf("\t-u - dumps PEB.GdiSharedHandleTable (default)\n");
	dprintf("\t-k - dumps WIN32K!gpentHmgr\n");
	dprintf("\t-a [filename] - text output\n");
	dprintf("\t-b [filename] - binary output\n\n");
	dprintf("\tFilter: (match only)\n");
	dprintf("\t-h <hex> - specific handle\n");
	dprintf("\t-p <hex> - specific pid\n");
	dprintf("\t-t <hex> - specific type:\n");
	for(unsigned int i=GDI_OBJTYPES::GDIObjType_DEF_TYPE;i<GDI_OBJTYPES::GDIObjType_MAX_TYPE;i++) {
		if(strstr(GDI_OBJTYPE_NAME[i], "UNUSED")) continue;
		dprintf("\t\t\t\t[%02lx]\t(%s)\n", i, GDI_OBJTYPE_NAME[i]);
	}
}

// dllmain
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

// !gdiobjdump
DECLARE_API (gdiobjdump)
{
	if (!args || !*args) {
		help(0,0,0,0,0);
		return;
	}

	ULONG searchhandle=0;
	ULONG searchpid=0;
	ULONG searchtype=0;

	DWORD actionmask = 0;

	char * outfilename = 0;

	if(strlen((char *)args) != 0) {
		char * token = strtok((char *)args, " ");
		while(token != NULL) {
			char * pEnd=0;

			if(_strcmpi(token, "-h") == 0) {
				char * szHandleToSearch = strtok(NULL, " ");
				if(szHandleToSearch == 0)
					break;
				searchhandle = strtoul(szHandleToSearch, &pEnd, 16);
				dprintf("Searching for handle %08lX...\n", searchhandle);
				actionmask |= SEARCH_HANDLE;
			} else if(_strcmpi(token, "-p") == 0) {
				char * szPid = strtok(NULL, " ");
				if(szPid == 0)
					break;
				searchpid = strtoul(szPid, &pEnd, 16);
				dprintf("Searching for Pid %08lX...\n", searchpid);
				actionmask |= SEARCH_PID;
			} else if(_strcmpi(token, "-t") == 0) {
				char * szSearchtype = strtok(NULL, " ");
				if(szSearchtype == 0)
					break;
				searchtype = strtoul(szSearchtype, &pEnd, 16);
				dprintf("Searching for type %08lX...\n", searchtype);
				actionmask |= SEARCH_TYPE;
			} else if(_strcmpi(token, "-k") == 0) {
				actionmask |= SEARCH_KERNEL;
			} else if(_strcmpi(token, "-b") == 0) {
				outfilename = strtok(NULL, " ");
				if(outfilename == 0) {
					dprintf("ERROR: -b requires output file name\n");
					return;
				}
				actionmask |= SEARCH_BINOUT;
				dprintf("Output File: %s\n", outfilename);
			} else if(_strcmpi(token, "-a") == 0) {
				outfilename = strtok(NULL, " ");
				if(outfilename == 0) {
					dprintf("ERROR: -a requires output file name\n");
					return;
				}
				actionmask |= SEARCH_ASCOUT;
				dprintf("Output File: %s\n", outfilename);
			}
			token = strtok(NULL, " ");
		}
	}

	GdiObjectLogger *pLogger = new GdiObjectLogger(actionmask);

	if(actionmask & SEARCH_BINOUT) {
		std::string cmd = ".\\winext\\GDIObjView.exe ";
		cmd.append(outfilename);
		pLogger->DumpTableData(outfilename, actionmask,searchhandle,searchpid,searchtype);
		WinExec(cmd.c_str(), SW_SHOW);
	} else {
		pLogger->LogOutput(outfilename, actionmask,searchhandle,searchpid,searchtype);
	}
	delete pLogger;
}
