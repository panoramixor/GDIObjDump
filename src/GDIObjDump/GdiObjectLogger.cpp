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

#include<fstream>

BOOL bSilent;

std::string outBuffer;		// virtual console

#define GDIENTRY_PROCESS(type, ka)	{ \
	type##64 *_processed = new type##64;	\
	memset(_processed, 0, sizeof(type##64));\
	if(ka == 0)\
		goto bail;\
	if(bIsX64) {\
		g_DataSpaces->ReadVirtual(ka, _processed, sizeof(type##64),  &tmp);\
	} else {\
	type##32 base={0};\
		g_DataSpaces->ReadVirtual(SIGN_EXTEND(ka), &base, sizeof(type##32), &tmp);\
		*_processed = base;\
	}\
	bail:\
	return _processed;\
}\

void dprint(char *format, ...)
{
	if(!bSilent) {
		va_list args;
		va_start(args, format);
		char __buffer[0x10000];

		memset(&__buffer, 0, sizeof(__buffer));

		vsprintf((char *)__buffer, format, args);
		outBuffer.append(__buffer);
		if(!bSilent)
			dprintf(__buffer);

		va_end(args);
	}
}

GdiObjectLogger::GdiObjectLogger(DWORD actionmask)
{
	bSilent = ((actionmask & SEARCH_BINOUT) || (actionmask & SEARCH_ASCOUT));
	InitSymbols(actionmask);
}

GdiObjectLogger::~GdiObjectLogger()
{
}

SURFACE64 * GdiObjectLogger::ProcessSURFACE(ULONG64 pKernelAddress)
{
	GDIENTRY_PROCESS(SURFACE, pKernelAddress);
}

void GdiObjectLogger::ProcessGDITABLEENTRY(GDICELL_64 *gdiEntry)
{
	gdiEntry->dump();
}

BASEOBJECT64 * GdiObjectLogger::ProcessBASEOBJECT(ULONG64 pKernelAddress)
{
	GDIENTRY_PROCESS(BASEOBJECT, pKernelAddress);
}

LFONT_ACTUAL64 * GdiObjectLogger::ProcessLFONT(ULONG64 pKernelAddress)
{
	GDIENTRY_PROCESS(LFONT_ACTUAL, pKernelAddress);
}

PALETTE64 * GdiObjectLogger::ProcessPALETTE(ULONG64 pKernelAddress)
{
	GDIENTRY_PROCESS(PALETTE, pKernelAddress);
}


UNKNOWNOBJ64 * GdiObjectLogger::ProcessUnknown(ULONG64 pKernelAddress)
{
	GDIENTRY_PROCESS(UNKNOWNOBJ, pKernelAddress);
}

COLORSPACE64 * GdiObjectLogger::ProcessCOLORSPACE(ULONG64 pKernelAddress)
{
	GDIENTRY_PROCESS(COLORSPACE, pKernelAddress);
}

GDICLRXFORM64 * GdiObjectLogger::ProcessCOLORTRANSFORM(ULONG64 pKernelAddress)
{
	GDIENTRY_PROCESS(GDICLRXFORM, pKernelAddress);
}

DWORD GdiObjectLogger::InitSymbols(DWORD actionmask)
{
	WCHAR * g_ImageNameW = new WCHAR[1024];
	HRESULT res = DebugCreate(__uuidof(IDebugClient), (void**)&g_Client);
	if(S_OK != res) {
		dprintf("ERROR: Cannot talk to dbgeng.dll\n");
		return -1;
	}

	g_Client->QueryInterface(__uuidof(IDebugControl), (void**)&g_Control);
    g_Client->QueryInterface(__uuidof(IDebugSymbols), (void**)&g_Symbols);
    g_Client->QueryInterface(__uuidof(IDebugSymbols2), (void**)&g_Symbols2);
	g_Client->QueryInterface(__uuidof(IDebugSymbols3), (void**)&g_Symbols3);

	g_Client->QueryInterface(__uuidof(IDebugDataSpaces), (void**)&g_DataSpaces);
	g_Client->QueryInterface(__uuidof(IDebugDataSpaces2), (void**)&g_DataSpaces2);
	g_Client->QueryInterface(__uuidof(IDebugDataSpaces3), (void**)&g_DataSpaces3);
	g_Client->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&g_DataSpaces4);

	g_Client->QueryInterface(__uuidof(IDebugAdvanced ), (void**)&g_Advanced);
	g_Client->QueryInterface(__uuidof(IDebugAdvanced2 ), (void**)&g_Advanced2);
	g_Client->QueryInterface(__uuidof(IDebugAdvanced3 ), (void**)&g_Advanced3);

	g_Client->QueryInterface(__uuidof(IDebugSystemObjects), (void**)&g_SystemObjects);

	// connect dbgeng.dll to the running debugger session
	res = g_Client->ConnectSession(DEBUG_CONNECT_SESSION_NO_VERSION | DEBUG_CONNECT_SESSION_NO_ANNOUNCE, NULL);
	if(S_OK != res) {
		dprintf("ERROR: Cannot connect dbgeng to current debugger session\n");
		return -1;
	}

	ULONG myclass = 0;
	ULONG qual = 0;

	g_Control->GetDebuggeeType(&myclass, &qual);

	if(myclass != DEBUG_CLASS_KERNEL) {
		dprintf("ERROR: This extension requires a Kernel Debugger session\n\n");
		return -1;
	}

	ULONG m_ActualMachine=0;
	ULONG m_Machine=0;

	g_Control->GetActualProcessorType(&m_ActualMachine);
	g_Control->GetEffectiveProcessorType(&m_Machine);
	if(m_Machine != m_ActualMachine) {
		// if under WOW64, load extensions
		g_Control->Execute(DEBUG_OUTCTL_IGNORE, "!wow64exts.sw", DEBUG_EXECUTE_NOT_LOGGED);
	}
	
	bIsX64 = (m_ActualMachine == IMAGE_FILE_MACHINE_AMD64) ? TRUE : FALSE;

	memset(g_ImageNameW, 0, (1024)*sizeof(WCHAR));

	DEBUG_VALUE _peb = {0};

	g_Control->Evaluate("$peb", DEBUG_VALUE_INT64, &_peb, NULL);
	g_PEB = _peb.I64;

	if(!g_PEB) {
		dprintf("ERROR: coudn't get PEB");
		return -1;
	}

	// reload symbols (none of this will work without correct symbols)
	g_Control->Execute(DEBUG_OUTCTL_IGNORE, ".reload /f ntdll.dll", DEBUG_EXECUTE_NOT_LOGGED);
	g_Control->Execute(DEBUG_OUTCTL_IGNORE, ".reload /f win32k.sys", DEBUG_EXECUTE_NOT_LOGGED);
	g_Control->Execute(DEBUG_OUTCTL_IGNORE, ".reload /f win32kbase.sys", DEBUG_EXECUTE_NOT_LOGGED);

	DEBUG_VALUE pid = {0};

	// get user mode Pid
	g_Control->Evaluate("$tpid", DEBUG_VALUE_INT32, &pid, NULL);
	g_UserPid=(ULONG)pid.I32;


	DEBUG_VALUE gpentHmgr = {0};
	g_Control->Evaluate("poi(win32k!gpentHmgr)", DEBUG_VALUE_INT64, &gpentHmgr, NULL);

	if(gpentHmgr.I64 == 0) {
		g_Control->Evaluate("poi(win32kbase!gpentHmgr)", DEBUG_VALUE_INT64, &gpentHmgr, NULL);
	}

	ULONG64 pProcessParameters = 0;

	ULONG moduleindex = 0;
	ULONG64 modulebase = 0;
	ULONG symboltypeid = 0;

	ULONG ProcessParametersOffset = 0;
	ULONG ImagePathNameOffset = 0;
	ULONG GdiSharedHandleTableOffset = 0;

	HRESULT hr = g_Symbols->GetModuleByModuleName("ntdll", 0, NULL, &modulebase);
	if(hr == S_OK) {
		dprint("NTDLL Base: %016I64x\n", modulebase);
	} else {
		hr = g_Symbols->GetSymbolModule("ntdll!", &modulebase);
		if(hr == S_OK) {
			dprint("NTDLL Base: %016I64x\n", modulebase);
		} else 
			dprintf("ERROR: cannot get NTDLL base\n");
			return -1;
	}

	dprint("PEB: %016I64x\n", g_PEB);
	dprint("Pid: %04x\n", g_UserPid);
	
	// get accurate offset from RTL_USER_PROCESS_PARAMETERS to RTL_USER_PROCESS_PARAMETERS.ImagePathName
	hr = g_Symbols->GetTypeId(modulebase, "_RTL_USER_PROCESS_PARAMETERS", &symboltypeid);
	if(hr == S_OK) {
		g_Symbols->GetFieldOffset(modulebase, symboltypeid, "ImagePathName", &ImagePathNameOffset);
	} else {
		dprintf("ERROR: unknown symbol _RTL_USER_PROCESS_PARAMETERS\n");
		return -1;
	}
	
	// get accurate offset from PEB to PEB.ProcessParameters 
	hr = g_Symbols->GetTypeId(modulebase, "_PEB", &symboltypeid);
	if(hr == S_OK) {
		g_Symbols->GetFieldOffset(modulebase, symboltypeid, "ProcessParameters", &ProcessParametersOffset);
	} else {
		dprintf("ERROR: unknown symbol _PEB\n");
		return -1;
	}

	// get accurate offset from PEB to PEB.GdiSharedHandleTable 
	hr = g_Symbols->GetFieldOffset(modulebase, symboltypeid, "GdiSharedHandleTable", &GdiSharedHandleTableOffset);
	if(hr != S_OK) {
		dprintf("ERROR: cannot get _PEB.GdiSharedHandleTable offset\n");
		return -1;
	}

	// read PEB.ProcessParameters 
	g_DataSpaces->ReadVirtual(g_PEB + (ULONG64)ProcessParametersOffset, &pProcessParameters, bIsX64 ? sizeof(ULONG64) : sizeof(ULONG), &tmp);				
	BYTE pImagePathName[1024];
	
	// read PEB.ProcessParameters->ImagePathName
	g_DataSpaces->ReadVirtual((pProcessParameters + (ULONG64)ImagePathNameOffset), &pImagePathName, bIsX64 ? sizeof(UNICODE_STRING64) : sizeof(UNICODE_STRING), &tmp);		
	ULONG64 pImagePathNameBufferW  = bIsX64 ? ((UNICODE_STRING64 *)(&pImagePathName))->Buffer : (ULONG)((UNICODE_STRING *)(&pImagePathName))->Buffer;

	unsigned int imagenamelen = bIsX64 ? ((UNICODE_STRING64 *)(&pImagePathName))->Length : (ULONG)((UNICODE_STRING *)(&pImagePathName))->Length;

	// read PEB.ProcessParameters->ImagePathName.Buffer
	g_DataSpaces->ReadVirtual(pImagePathNameBufferW, g_ImageNameW, imagenamelen, &tmp);
	dprint("Imagename %S\n", g_ImageNameW);

	// get GdiSharedHandleTable
	g_DataSpaces->ReadVirtual(g_PEB + (ULONG64)GdiSharedHandleTableOffset, &pGdiSharedHandleTable, bIsX64 ? sizeof(ULONG64) : sizeof(ULONG), &tmp);
	dprint("GdiSharedHandleTable:\t\t%016I64x (Kernel)\n\t\t\t\t\t%016I64x (User)\n", gpentHmgr.I64,  pGdiSharedHandleTable);

	// use kernel table ?
	if(actionmask & SEARCH_KERNEL) 
		pGdiSharedHandleTable = gpentHmgr.I64;


	return 0;

}

void GdiObjectLogger::RefreshList(DWORD actionmask, ULONG searchhandle, ULONG searchpid, ULONG searchtype)
{
	ULONG GDIOBJSize = bIsX64 ? sizeof(GDICELL_64) : sizeof(GDICELL_32);

	tmp=0;
	DWORD maxcells=0;

	gdiObjectsX64.clear();

	GDICELL_64 *tmpCellTable64;// = new GDICELL_64[MAX_GDI_CELLS];

	DWORD __totalbytes;

	if(actionmask & SEARCH_KERNEL) 	{
		tmpCellTable64 = new GDICELL_64[MAX_GDI_CELLS];
		if(bIsX64) {
			g_DataSpaces->ReadVirtualUncached(pGdiSharedHandleTable, tmpCellTable64, GDIOBJSize*MAX_GDI_CELLS, &__totalbytes);
		} else {
			GDICELL_32 *tmpCellTable32 = new GDICELL_32[MAX_GDI_CELLS];
			g_DataSpaces->ReadVirtualUncached(SIGN_EXTEND(pGdiSharedHandleTable), tmpCellTable32, GDIOBJSize*MAX_GDI_CELLS, &__totalbytes);
			*tmpCellTable64 = *tmpCellTable32;
		}
		maxcells = __totalbytes/(DWORD)GDIOBJSize;

	} else {
		std::string readvec;
		int retry=0;

		DWORD ofs = 0;
		while(ofs<0x4000*GDIOBJSize) {
			BYTE _readBuffer[0x4000*sizeof(GDICELL_64)] = {0};
			__totalbytes = 0;

			DWORD bytestoread = sizeof(_readBuffer);

			HRESULT hr = g_DataSpaces->ReadVirtual(pGdiSharedHandleTable+ofs, _readBuffer, bytestoread, &__totalbytes);
			DWORD aligned = (__totalbytes/GDIOBJSize)*GDIOBJSize;
			if(hr == S_OK)  {
				if(__totalbytes == aligned)		// was able to read it all?
					ofs += aligned;
				else
					ofs += aligned + GDIOBJSize;
			} else {
				DWORD lastofspage = ofs/0x1000;
				ofs += 0xff0;
				while(lastofspage == ofs/0x1000)
				{
					ofs += GDIOBJSize;
				}

				retry++;
			}
			readvec.append((char *)_readBuffer, aligned);
		}
		dprintf("entries found: %08lx\n", readvec.size()/sizeof(GDICELL_64));
		dprintf("retries: %08lx\n", retry);

		tmpCellTable64 = new GDICELL_64[MAX_GDI_CELLS];
		memcpy(tmpCellTable64, readvec.c_str(), readvec.size());
		maxcells = (DWORD)readvec.size()/(DWORD)GDIOBJSize;
	}

	// read GdiSharedHandleTable entries and filter according to user arguments
	DWORD i=0;

	for(i=0;i<maxcells;i++) {
		GDICELL_64 gdiobjProcessed = tmpCellTable64[i];
		// peek handle from BASEOBJECT

		BASEOBJECT64 *tmpBase = ProcessBASEOBJECT((ULONG64)gdiobjProcessed.pKernelAddress);
		gdiBaseVec.push_back(*tmpBase);
		delete tmpBase;
		gdiObjectsX64.push_back(gdiobjProcessed);
	}

	delete tmpCellTable64;

	// apply filter
	std::vector<GDICELL_64> tmpcells;
	std::vector<BASEOBJECT64> tmpbase;

	for (unsigned int i=0;i<gdiObjectsX64.size();i++)	{
		if((actionmask & SEARCH_TYPE) && (LOBYTE(gdiObjectsX64[i].wType) != searchtype)) continue;
		if((actionmask & SEARCH_HANDLE) && (gdiBaseVec[i].hHmgr != searchhandle)) continue;
		if((actionmask & SEARCH_PID) && (gdiObjectsX64[i].wProcessId != searchpid)) continue;
		tmpcells.push_back(gdiObjectsX64[i]);
		tmpbase.push_back(gdiBaseVec[i]);
	}
	gdiObjectsX64 = tmpcells;
	gdiBaseVec = tmpbase;
}


void GdiObjectLogger::LogOutput(char *filename, DWORD actionmask, ULONG searchhandle, ULONG searchpid, ULONG searchtype)
{
	gdiSurfVec.clear();
	gdiBaseVec.clear();
	gdiPaletteVec.clear();
	gdiFontVec.clear();
	gdiColorSpaceVec.clear();
	gdiColorTransVec.clear();
	gdiUnknownVec.clear();

	// refresh local gdi object list
	RefreshList(actionmask, searchhandle, searchpid, searchtype);

	ULONG64 pToBits=0;
	HANDLE bitmaphandle=0;

	// list matching Gdi Objects
	for (std::vector<GDICELL_64>::iterator iter = gdiObjectsX64.begin(); iter != gdiObjectsX64.end(); ++iter)
	{
		// dump GDI_TABLE_ENTRY
		ProcessGDITABLEENTRY((GDICELL_64 *)iter._Ptr);

		// dump BASEOBJECT (common to all types)
		BASEOBJECT64 *tmpBase = ProcessBASEOBJECT((ULONG64)iter->pKernelAddress);
		gdiBaseVec.push_back(*tmpBase);
		delete tmpBase;

		// type specific processing
		switch(LOBYTE(iter->wType)) {
			case GDI_OBJTYPES::GDIObjType_SURF_TYPE:
				{
					SURFACE64 *tmp = ProcessSURFACE((ULONG64)iter->pKernelAddress);
					gdiSurfVec.push_back(*tmp);
					tmp->dump();
					delete tmp;
				}
				break;

			case GDI_OBJTYPES::GDIObjType_PAL_TYPE:
				{
					PALETTE64 *tmp = ProcessPALETTE((ULONG64)iter->pKernelAddress);
					gdiPaletteVec.push_back(*tmp);
					tmp->dump();
					delete tmp;
				}
				break;

			case GDI_OBJTYPES::GDIObjType_LFONT_TYPE:
				{
					LFONT_ACTUAL64 *tmp = ProcessLFONT((ULONG64)iter->pKernelAddress);
					gdiFontVec.push_back(*tmp);
					tmp->dump();
					delete tmp;
				}			
				break;

			case GDI_OBJTYPES::GDIObjType_ICMLCS_TYPE:
				{
					COLORSPACE64 *tmp = ProcessCOLORSPACE((ULONG64)iter->pKernelAddress);
					gdiColorSpaceVec.push_back(*tmp);
					tmp->dump();
					delete tmp;
				}
				break;

			case GDI_OBJTYPES::GDIObjType_ICMCXF_TYPE:
				{
					GDICLRXFORM64 *tmp = ProcessCOLORTRANSFORM((ULONG64)iter->pKernelAddress);
					gdiColorTransVec.push_back(*tmp);
					tmp->dump();
					delete tmp;
				}
				break;

			default:
				{
					UNKNOWNOBJ64 *tmp = ProcessUnknown((ULONG64)iter->pKernelAddress);
					gdiUnknownVec.push_back(*tmp);
					delete tmp;
				}
				break;
		}

	}

	if(filename) {
		std::fstream file;
		file.open(filename, std::ios::out | std::ios::binary);
		file.write((char *)outBuffer.c_str(), outBuffer.size());
		file.close();	
	}
}

void GdiObjectLogger::DumpTableData(char *filename, DWORD actionmask, ULONG searchhandle, ULONG searchpid, ULONG searchtype)
{
	gdiSurfVec.clear();
	gdiBaseVec.clear();
	gdiPaletteVec.clear();
	gdiFontVec.clear();
	gdiColorSpaceVec.clear();
	gdiColorTransVec.clear();
	gdiUnknownVec.clear();

	// refresh local gdi object list
	RefreshList(0, 0, 0, 0);

	// list matching Gdi Objects
	for (std::vector<GDICELL_64>::iterator iter = gdiObjectsX64.begin(); iter != gdiObjectsX64.end(); ++iter)
	{
		// dump GDI_TABLE_ENTRY
		ProcessGDITABLEENTRY((GDICELL_64 *)iter._Ptr);

		// dump BASEOBJECT (common to all types)
		BASEOBJECT64 *tmpBase = ProcessBASEOBJECT((ULONG64)iter->pKernelAddress);
		gdiBaseVec.push_back(*tmpBase);
		delete tmpBase;

		// type specific processing
		switch(LOBYTE(iter->wType)) {
			case GDI_OBJTYPES::GDIObjType_SURF_TYPE:
				{
					SURFACE64 *tmp = ProcessSURFACE((ULONG64)iter->pKernelAddress);
					gdiSurfVec.push_back(*tmp);
					delete tmp;
				}
				break;

			case GDI_OBJTYPES::GDIObjType_PAL_TYPE:
				{
					PALETTE64 *tmp = ProcessPALETTE((ULONG64)iter->pKernelAddress);
					gdiPaletteVec.push_back(*tmp);
					delete tmp;
				}
				break;

			case GDI_OBJTYPES::GDIObjType_LFONT_TYPE:
				{
					LFONT_ACTUAL64 *tmp = ProcessLFONT((ULONG64)iter->pKernelAddress);
					gdiFontVec.push_back(*tmp);
					delete tmp;
				}			
				break;

			case GDI_OBJTYPES::GDIObjType_ICMLCS_TYPE:
				{
					COLORSPACE64 *tmp = ProcessCOLORSPACE((ULONG64)iter->pKernelAddress);
					gdiColorSpaceVec.push_back(*tmp);
					delete tmp;
				}
				break;

			case GDI_OBJTYPES::GDIObjType_ICMCXF_TYPE:
				{
					GDICLRXFORM64 *tmp = ProcessCOLORTRANSFORM((ULONG64)iter->pKernelAddress);
					gdiColorTransVec.push_back(*tmp);
					delete tmp;
				}
				break;

			default:
				{
					UNKNOWNOBJ64 *tmp = ProcessUnknown((ULONG64)iter->pKernelAddress);
					gdiUnknownVec.push_back(*tmp);
					delete tmp;
				}
				break;
		}
	}

	GDIDUMP *dumphdr = new GDIDUMP;

	dumphdr->numgdientries = (DWORD)gdiObjectsX64.size();
	dumphdr->numsurfaces = (DWORD) gdiSurfVec.size();
	dumphdr->numpalettes = (DWORD) gdiPaletteVec.size();
	dumphdr->numcolorspace = (DWORD) gdiColorSpaceVec.size();
	dumphdr->numcolortrans = (DWORD) gdiColorTransVec.size();
	dumphdr->nunfonts = (DWORD) gdiFontVec.size();
	dumphdr->numother = (DWORD) gdiUnknownVec.size();
	
	std::fstream file;
	file.open(filename, std::ios::out | std::ios::binary);
	file.write((char *)dumphdr, sizeof(GDIDUMP));
	if(dumphdr->numgdientries) {
		file.write((char *)&gdiObjectsX64[0], sizeof(GDICELL_64)*dumphdr->numgdientries);
		file.write((char *)&gdiBaseVec[0], sizeof(BASEOBJECT64)*dumphdr->numgdientries);
	}
	if(dumphdr->numsurfaces)
		file.write((char *)&gdiSurfVec[0], sizeof(SURFACE64)*dumphdr->numsurfaces);
	if(dumphdr->numpalettes)
		file.write((char *)&gdiPaletteVec[0], sizeof(PALETTE64)*dumphdr->numpalettes);
	if(dumphdr->numcolorspace)
		file.write((char *)&gdiColorSpaceVec[0], sizeof(COLORSPACE64)*dumphdr->numcolorspace);
	if(dumphdr->numcolortrans)
		file.write((char *)&gdiColorTransVec[0], sizeof(GDICLRXFORM64)*dumphdr->numcolortrans);
	if(dumphdr->nunfonts)
		file.write((char *)&gdiFontVec[0], sizeof(LFONT_ACTUAL64)*dumphdr->nunfonts);
	if( dumphdr->numother)
		file.write((char *)&gdiUnknownVec[0], sizeof(UNKNOWNOBJ64)*dumphdr->numother);

	file.close();

	delete dumphdr;
}

