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


#ifndef __GdiObjectLogger____
	#define __GdiObjectLogger____

// search constants
#define SEARCH_HANDLE	0x0001
#define SEARCH_TYPE		SEARCH_HANDLE<<1
#define SEARCH_PID		SEARCH_HANDLE<<2
#define SEARCH_KERNEL	SEARCH_HANDLE<<3
#define SEARCH_BINOUT	SEARCH_HANDLE<<4
#define SEARCH_ASCOUT	SEARCH_HANDLE<<5

class GdiObjectLogger
{
	private:
		ULONG tmp;

		IDebugClient* g_Client;

		IDebugControl* g_Control;
		IDebugSymbols* g_Symbols;
		IDebugSymbols2* g_Symbols2;
		IDebugSymbols3* g_Symbols3;

		IDebugDataSpaces* g_DataSpaces;
		IDebugDataSpaces2* g_DataSpaces2;
		IDebugDataSpaces3* g_DataSpaces3;
		IDebugDataSpaces4* g_DataSpaces4;

		IDebugSystemObjects *g_SystemObjects;

		IDebugAdvanced *g_Advanced;
		IDebugAdvanced2 *g_Advanced2;
		IDebugAdvanced3 *g_Advanced3;

		BOOL bIsX64;

		WCHAR * g_ImageNameW;
		ULONG g_UserPid;

		ULONG64 pGdiSharedHandleTable;
		ULONG64 g_PEB;

		// cells
		std::vector<GDICELL_64> gdiObjectsX64;

		std::vector<SURFACE64> gdiSurfVec;
		std::vector<BASEOBJECT64> gdiBaseVec;
		std::vector<PALETTE64> gdiPaletteVec;
		std::vector<LFONT_ACTUAL64> gdiFontVec;
		std::vector<COLORSPACE64> gdiColorSpaceVec;
		std::vector<GDICLRXFORM64> gdiColorTransVec;
		
		std::vector<UNKNOWNOBJ64> gdiUnknownVec;

	public:
		void RefreshList(DWORD actionmask, ULONG searchhandle, ULONG searchpid, ULONG searchtype);


		void ProcessGDITABLEENTRY(GDICELL_64 *gdiEntry);
		BASEOBJECT64 * ProcessBASEOBJECT(ULONG64 pKernelAddress);

		SURFACE64 * ProcessSURFACE(ULONG64 pKernelAddress);
		PALETTE64 * ProcessPALETTE(ULONG64 pKernelAddress);
		LFONT_ACTUAL64 * ProcessLFONT(ULONG64 pKernelAddress);
		COLORSPACE64 * ProcessCOLORSPACE(ULONG64 pKernelAddress);
		GDICLRXFORM64 * ProcessCOLORTRANSFORM(ULONG64 pKernelAddress);
		UNKNOWNOBJ64 * ProcessUnknown(ULONG64 pKernelAddress);

		GdiObjectLogger(DWORD actionmask);
		~GdiObjectLogger();
		
		void LogOutput(char *args, DWORD actionmask, ULONG searchhandle, ULONG searchpid, ULONG searchtype);
		void GdiObjectLogger::DumpTableData(char *filename, DWORD actionmask, ULONG searchhandle, ULONG searchpid, ULONG searchtype);

		DWORD InitSymbols(DWORD actionmask);
};



#endif // __GdiObjectLogger____
