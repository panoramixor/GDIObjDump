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
#include "Shellapi.h"
#include "resource.h"
#include "GDIObjView.h"
#include "GdiTableVis.h"
#include <fstream>
#include <Commdlg.h>
#include "GdiDumpStruct.h"
#include "Windowsx.h"

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

// Forward declarations of functions included in this code module:
ATOM				RegisterMainWndClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

GdiTableVis *pGdiTableVis;

HWND hWndParent;

HANDLE ht_GdiTableVis;		// grapher thread

WCHAR gDumpFileName[1024];

std::vector<GDICELL_64> gdiCellVec;
std::vector<SURFACE64> gdiSurfVec;
std::vector<BASEOBJECT64> gdiBaseVec;
std::vector<PALETTE64> gdiPaletteVec;
std::vector<LFONT_ACTUAL64> gdiFontVec;
std::vector<COLORSPACE64> gdiColorSpaceVec;
std::vector<GDICLRXFORM64> gdiColorTransVec;
std::vector<UNKNOWNOBJ64> gdiUnknownVec;

DWORD searchtype = 0;
DWORD searchhandle=0;
DWORD searchpid=0;
DWORD action=SHOW_UNUSED;

std::string outBuffer;

void ReplaceStringInPlace(std::string& subject, const std::string& search,
                          const std::string& replace) {
    size_t pos = 0;
    while((pos = subject.find(search, pos)) != std::string::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
}

// HWNDs
HWND hEdit;
HWND hFilter;
HWND hSort;

// sorting related
typedef struct _SORTERDATA {
	DWORD index;
	GDICELL_64 cell;
	BASEOBJECT64 base;
} SORTERDATA;

std::vector<SORTERDATA> gSorterVec;

#define SORTER(name, type, proper) \
	bool Comp##name##(const type## &struct1, const type## &struct2)\
	{\
		return (struct1.##proper## < struct2.##proper##);\
	}\

SORTER(Address, SORTERDATA, cell.pKernelAddress);
SORTER(Handle, SORTERDATA, base.hHmgr);
SORTER(Index, SORTERDATA, index);

// handle searching
#define CHECK_HANDLE(type, vec) \
	for (std::vector<##type##>::iterator iter = vec##.begin(); iter != vec##.end(); ++iter)	{\
				ULONG64 handle = base.hHmgr; \
				ULONG64 basehandle = (iter->BaseObject.hHmgr);\
				if(handle == basehandle) {\
					iter->dump();\
					break;\
				}\
	}\

// printing 
#define DPRINTF_START() outBuffer.clear();
#define DPRINTF_END() SetWindowTextA(hEdit, (LPCSTR)outBuffer.c_str());

void hexdump(unsigned char *buffer, unsigned long len, unsigned long width)
 {
  unsigned long i;
  for (i=0;i<len;i++)
	{
		dprintf("%02x ",buffer[i]);
		if(((i+1) % width) == 0)
		{/*
			dprintf(":");
			for (unsigned int j=i+1-width;j<i;j++)
			{
				unsigned char a = buffer[j] & 0x7f;
				dprintf(".");
				if(a == 0) dprintf(".");
				else if (a < 32) dprintf(".", a);
				else dprintf("%c",a);
			}*/
			dprintf("\n");
		}
	}
 }


void dprintf(char *format, ...)
{
	va_list args;
	va_start(args, format);
	char __buffer[0x10000];

	memset(&__buffer, 0, sizeof(__buffer));

	vsprintf((char *)__buffer, format, args);

	outBuffer.append(__buffer);

	ReplaceStringInPlace(outBuffer, "\n", "\r\n");
	ReplaceStringInPlace(outBuffer, "\t", "  ");

	va_end(args);
}

void DumpBase(DWORD index)
{

	DPRINTF_START()		// custom macro for fast 1 pass text printing on edit control

	GDICELL_64 gdiobj = gdiCellVec.at(index);
	gdiobj.dump();

	BASEOBJECT64 base = gdiBaseVec.at(index);
	base.dump();

	switch(LOBYTE(gdiobj.wType)) 
	{
		case GDIObjType_SURF_TYPE:
			CHECK_HANDLE(SURFACE64, gdiSurfVec);
			break;

		case GDIObjType_PAL_TYPE:
			CHECK_HANDLE(PALETTE64, gdiPaletteVec);
			break;

		case GDIObjType_LFONT_TYPE:
			CHECK_HANDLE(LFONT_ACTUAL64, gdiFontVec);
			break;

		case GDIObjType_ICMLCS_TYPE:
			CHECK_HANDLE(COLORSPACE64, gdiColorSpaceVec);
			break;

		case GDIObjType_ICMCXF_TYPE:
			CHECK_HANDLE(GDICLRXFORM64, gdiColorTransVec);
			break;

		default:
			CHECK_HANDLE(UNKNOWNOBJ64, gdiUnknownVec);
			break;
	}
	DPRINTF_END()	// custom macro for fast 1 pass text printing on edit control
}

void ApplySort()
{
	if(Button_GetCheck(GetDlgItem(hSort, IDC_SORTBYADDRESS))) {
		std::sort(gSorterVec.begin(), gSorterVec.end(), CompAddress);
	} else if(Button_GetCheck(GetDlgItem(hSort, IDC_SORTBYHANDLE))) {
		std::sort(gSorterVec.begin(), gSorterVec.end(), CompHandle);
	} else if(Button_GetCheck(GetDlgItem(hSort, IDC_SORTBYINDEX))) {
		std::sort(gSorterVec.begin(), gSorterVec.end(), CompIndex);
	}

	if(Button_GetCheck(GetDlgItem(hSort, IDC_SORTDESC))) {
		std::reverse(gSorterVec.begin(),gSorterVec.end());
	}

	for(unsigned int i=0;i<gdiCellVec.size();i++) {
		gdiCellVec[i] = gSorterVec[i].cell;
		gdiBaseVec[i] = gSorterVec[i].base;
	}
}

void ReadDumpFile(WCHAR *filename, DWORD actionmask, DWORD searchtype, DWORD searchhandle, DWORD searchpid)
{
	gdiCellVec.clear();
	gdiBaseVec.clear();
	gdiSurfVec.clear();
	gdiPaletteVec.clear();
	gdiColorSpaceVec.clear();
	gdiColorTransVec.clear();
	gdiFontVec.clear();
	gdiUnknownVec.clear();

	GDIDUMP hdr = {0};
	
	std::fstream file;
	file.open(filename, std::ios::in | std::ios::binary);
	file.read((char *)&hdr, sizeof(GDIDUMP));

	gdiCellVec.resize(hdr.numgdientries);
	gdiBaseVec.resize(hdr.numgdientries);
	gdiSurfVec.resize(hdr.numsurfaces);
	gdiPaletteVec.resize(hdr.numpalettes);
	gdiColorSpaceVec.resize(hdr.numcolorspace);
	gdiColorTransVec.resize(hdr.numcolortrans);
	gdiFontVec.resize(hdr.nunfonts);
	gdiUnknownVec.resize(hdr.numother);

	if(hdr.numgdientries) {
		file.read((char *)&gdiCellVec[0], sizeof(GDICELL_64)*hdr.numgdientries);
		file.read((char *)&gdiBaseVec[0], sizeof(BASEOBJECT64)*hdr.numgdientries);
	}

	if(hdr.numsurfaces)
		file.read((char *)&gdiSurfVec[0], sizeof(SURFACE64)*hdr.numsurfaces);
	if(hdr.numpalettes)
		file.read((char *)&gdiPaletteVec[0], sizeof(PALETTE64)*hdr.numpalettes);
	if(hdr.numcolorspace)
		file.read((char *)&gdiColorSpaceVec[0], sizeof(COLORSPACE64)*hdr.numcolorspace);
	if(hdr.numcolortrans)
		file.read((char *)&gdiColorTransVec[0], sizeof(GDICLRXFORM64)*hdr.numcolortrans);
	if(hdr.nunfonts)
		file.read((char *)&gdiFontVec[0], sizeof(LFONT_ACTUAL64)*hdr.nunfonts);
	if(hdr.numother)
		file.read((char *)&gdiUnknownVec[0], sizeof(UNKNOWNOBJ64)*hdr.numother);

	file.close();

	// apply filter
	std::vector<GDICELL_64> tmpcells;
	std::vector<BASEOBJECT64> tmpbase;

	for (unsigned int i=0;i<gdiCellVec.size();i++)	{
		if((actionmask & SEARCH_TYPE) && (LOBYTE(gdiCellVec[i].wType) != searchtype)) continue;
		if((actionmask & SEARCH_HANDLE) && (gdiBaseVec[i].hHmgr != searchhandle)) continue;
		if((actionmask & SEARCH_PID) && (gdiCellVec[i].wProcessId != searchpid)) continue;
		if((!(actionmask & SHOW_UNUSED)) && ((ULONG64)gdiCellVec[i].pKernelAddress <= 0xFFFF)) continue;

		if(LOBYTE(gdiCellVec[i].wType) >= GDIObjType_MAX_TYPE) {
			gdiCellVec[i].wType = (gdiCellVec[i].wType & 0xFF00) | GDIObjType_MAX_TYPE;
		}


		tmpcells.push_back(gdiCellVec[i]);
		tmpbase.push_back(gdiBaseVec[i]);
	}

	gdiCellVec = tmpcells;
	gdiBaseVec = tmpbase;

	gSorterVec.resize(gdiCellVec.size());

	for(unsigned int i=0;i<gdiCellVec.size();i++) {
		gSorterVec[i].index = i;
		gSorterVec[i].cell = gdiCellVec[i];
		gSorterVec[i].base = gdiBaseVec[i];
	}
}

DWORD WINAPI GdiTableVisThread( LPVOID lpParam ) 
{ 
	pGdiTableVis = new GdiTableVis;
	LPWSTR *szArglist;
	int nArgs;
	szArglist = CommandLineToArgvW(GetCommandLine(), &nArgs);
	dprintf("Reading %s", szArglist[1]);
	lstrcpyn(gDumpFileName, szArglist[1], 1024);
	ReadDumpFile(gDumpFileName, SHOW_UNUSED, 0,0,0);
	pGdiTableVis->SetTable(gdiCellVec);
	pGdiTableVis->WinMain();
	delete pGdiTableVis;
	return 0;
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	HANDLE hGDIObjViewSingleInstanceMutex = CreateMutex(NULL, FALSE, L"GDIObjViewSingleInstanceMutex");
	if(GetLastError() == ERROR_ALREADY_EXISTS) {
		HWND hMain = FindWindow(L"GDIObjView", NULL);
		SendMessage(hMain, WM_COMMAND, ID_VIEW_REFRESH, 0);
		return 0;
	}

	MSG msg;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_DISPLAYAPP, szWindowClass, MAX_LOADSTRING);


	RegisterMainWndClass(hInstance);

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0))
	{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
	}

	return (int) msg.wParam;
}


// sorting options
BOOL CALLBACK SortDlgProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	BOOL bRefresh = FALSE;		// set this if refresh of list is needed

    switch(Message)
    {
		case WM_CLOSE:
			CheckMenuItem(GetMenu(hWndParent), ID_VIEW_SORT, MF_UNCHECKED);
			EndDialog(hwnd, 0);
			break;

		case WM_INITDIALOG:
			{
				CheckRadioButton(hwnd, IDC_SORTBYINDEX, IDC_SORTBYADDRESS, IDC_SORTBYINDEX);
				CheckRadioButton(hwnd, IDC_SORTASC, IDC_SORTDESC, IDC_SORTASC);
			}
			break;

        case WM_COMMAND:

            switch(LOWORD(wParam))
            {
				case IDC_SORTBYINDEX:
				case IDC_SORTBYADDRESS:
				case IDC_SORTBYHANDLE:
				case IDC_SORTASC:
				case IDC_SORTDESC:
					bRefresh = TRUE;
					break;

				default:
					break;
			}
			break;
		
		default:
			return FALSE;
	}

	if(bRefresh) {
		ShowWindow(pGdiTableVis->hWnd, SW_HIDE);
		ApplySort();
		pGdiTableVis->SetTable(gdiCellVec);
		ShowWindow(pGdiTableVis->hWnd, SW_SHOW);
	}
	return TRUE;
}

// filter options
BOOL CALLBACK FilterDlgProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	BOOL bRefresh = FALSE;		// set this if refresh of list is needed

    switch(Message)
    {
		case WM_CLOSE:
			CheckMenuItem(GetMenu(hWndParent), ID_VIEW_FILTER, MF_UNCHECKED);
			EndDialog(hwnd, 0);
			break;

		case WM_INITDIALOG:
			{
				for(unsigned int i=GDIObjType_DEF_TYPE;i<GDIObjType_MAX_TYPE;i++) {
					ComboBox_AddString(GetDlgItem(hwnd, IDC_COMBOTYPES), GDI_OBJTYPE_NAMEW[i]);
				}
				ComboBox_SelectString(GetDlgItem(hwnd, IDC_COMBOTYPES), 0, GDI_OBJTYPE_NAMEW[0]);
				Button_SetCheck(GetDlgItem(hwnd, IDC_CHECKUNUSED), BST_CHECKED);
			}
			return TRUE;

        case WM_COMMAND:
			if(HIWORD(wParam) == CBN_SELCHANGE)	{
				searchtype = ComboBox_GetCurSel((HWND)lParam);
				if(searchtype)
					action |= SEARCH_TYPE;
				else
					action &= ~SEARCH_TYPE;
				bRefresh = TRUE;
				break;
			}

            switch(LOWORD(wParam))
            {
				case IDC_EDITHANDLE:
					{
						char text[20] = {0};
						GetWindowTextA((HWND)lParam, text, 16);
						char * end;
						searchhandle = strtoul(text, &end, 16);
						if(searchhandle) {
							action |= SEARCH_HANDLE;
						} else {
							action &= ~SEARCH_HANDLE;
						}
						bRefresh = TRUE;
					}
					break;

				case IDC_EDITPID:
					{
						char text[20] = {0};
						GetWindowTextA((HWND)lParam, text, 16);
						char * end;
						searchpid = strtoul(text, &end, 16);
						if(strlen(text))
							action |= SEARCH_PID;
						else 
							action &= ~SEARCH_PID;
						bRefresh = TRUE;

					}
					break;

                case IDC_CHECKTYPE:
					{
						BOOL isChecked = Button_GetCheck(GetDlgItem(hwnd, IDC_CHECKTYPE));
						EnableWindow(GetDlgItem(hwnd, IDC_COMBOTYPES), isChecked);

						if(isChecked)
						{
							searchtype = ComboBox_GetCurSel(GetDlgItem(hwnd, IDC_COMBOTYPES));
							if(searchtype)
								action |= SEARCH_TYPE;
							else
								action &= ~SEARCH_TYPE;
						} else {
							action &= ~SEARCH_TYPE;
						}
						bRefresh = TRUE;
					}
					break;

                case IDC_CHECKUNUSED:
					{
						BOOL isChecked = Button_GetCheck(GetDlgItem(hwnd, IDC_CHECKUNUSED));
						if(isChecked) {
							action |= SHOW_UNUSED;
						} else {
							action &= ~SHOW_UNUSED;
						}
						bRefresh = TRUE;
					}
					break;

                case IDC_CHECKPID:
					{
						BOOL isChecked = Button_GetCheck(GetDlgItem(hwnd, IDC_CHECKPID));
						EnableWindow(GetDlgItem(hwnd, IDC_EDITPID), isChecked);

						if(isChecked)
						{
							char text[20] = {0};
							GetWindowTextA((HWND)GetDlgItem(hwnd, IDC_EDITPID), text, 16);
							char * end;
							searchpid = strtoul(text, &end, 16);
							if(strlen(text))
								action |= SEARCH_PID;
							else 
								action &= ~SEARCH_PID;
						} else {
							action &= ~SEARCH_PID;
						}
						bRefresh = TRUE;
					}
					break;

                case IDC_CHECKHANDLE:
					{
						BOOL isChecked = Button_GetCheck(GetDlgItem(hwnd, IDC_CHECKHANDLE));
						EnableWindow(GetDlgItem(hwnd, IDC_EDITHANDLE), isChecked);
						if(isChecked)
						{
							char text[20] = {0};
							GetWindowTextA(GetDlgItem(hwnd, IDC_EDITHANDLE), text, 16);
							char * end;
							searchhandle = strtoul(text, &end, 16);
							if(searchhandle) {
								action |= SEARCH_HANDLE;
							} else {
								action &= ~SEARCH_HANDLE;
							}
						} else {
							action &= ~SEARCH_HANDLE;
						}
						bRefresh = TRUE;
					}
					break;
            }
			break;

		default:
            return FALSE;
    }

	if(bRefresh) {
		ShowWindow(pGdiTableVis->hWnd, SW_HIDE);
		ReadDumpFile(gDumpFileName, action, searchtype, searchhandle, searchpid);
		ApplySort();
		pGdiTableVis->SetTable(gdiCellVec);
		ShowWindow(pGdiTableVis->hWnd, SW_SHOW);
	}

    return TRUE;
}

ATOM RegisterMainWndClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_DISPLAYAPP));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_DISPLAYAPP);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

// Custom edit control
LRESULT CALLBACK EditWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	HideCaret(hwnd);
    switch (msg)
    {
         case WM_KEYDOWN:
			SendMessage(hWndParent, WM_KEYDOWN, wparam, lparam);
            return 0;

		default:
			break;
    }
    return DefSubclassProc(hwnd, msg, wparam, lparam);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	HWND hWnd;
	hInst = hInstance; // Store instance handle in our global variable

	RECT desktop;
	SystemParametersInfo(SPI_GETWORKAREA,NULL,&desktop,NULL);

	hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, desktop.left, desktop.top, 1024, desktop.bottom/2, NULL, NULL, hInstance, NULL);

	if (!hWnd)
		return FALSE;

	hWndParent = hWnd;

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	RECT rect = {0};
	GetClientRect(hWndParent, &rect);
	int width = (rect.right-rect.left);
	int halfwidth = width/2;
	int height = (rect.bottom-rect.top);

	hEdit = CreateWindow(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, rect.right-450, 0, 450, height, hWnd, 0, hInst, NULL);
	SetWindowSubclass(hEdit, EditWndProc, 0, 0);

	HFONT hFont = CreateFont(8 , 8, 0 , 0 , FW_DONTCARE , FALSE , FALSE , FALSE , DEFAULT_CHARSET , OUT_OUTLINE_PRECIS , CLIP_DEFAULT_PRECIS , 0 , FF_DONTCARE,TEXT ( "Fixedsys" ) );
	SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, 0);

	hFilter = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FILTERDLG), hWnd, (DLGPROC)FilterDlgProc);
	hSort = CreateDialog(hInst, MAKEINTRESOURCE(IDD_SORTDLG), hWnd, (DLGPROC)SortDlgProc);

	return TRUE;
}


// Main (parent) window
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;
	RECT rect={0};
	HBRUSH      tmpBrush;

	switch (message)
	{
		case WM_KEYDOWN: 
			// F5 = refresh
			if(VK_F5 == (wParam)) {
				SendMessage(hWnd, WM_COMMAND, ID_VIEW_REFRESH, 0);
			}

			// F3 = open file
			if(VK_F3 == (wParam)) {
				SendMessage(hWnd, WM_COMMAND, ID_FILE_OPEN, 0);
			}
			break;

		case WM_MOUSEWHEEL:
//			SendMessage(hWndParent, WM_MOUSEWHEEL, wParam, lParam);
			break;

		case WM_ERASEBKGND:
			{
				GetClientRect(hWnd, &rect);

				hdc = (HDC)wParam;
				tmpBrush = CreateSolidBrush(COLORREF(RGB(0,0,0)));
				FillRect(hdc, &rect, tmpBrush);
				DeleteObject(tmpBrush);
			}
			break;

		case WM_CREATE:
			{
				DWORD tid;
				ht_GdiTableVis = CreateThread(0, 0, &GdiTableVisThread, 0, 0, &tid);
			}
			break;

		case WM_COMMAND:
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
		
			// Parse the menu selections:
			switch (wmId)
			{
				case IDM_ABOUT:
					DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
					break;

				case ID_VIEW_FILTER:
					{
						CheckMenuItem(GetMenu(hWnd), ID_VIEW_FILTER, MF_CHECKED);
						ShowWindow(hFilter, SW_SHOW);
					}
					break;

				case ID_VIEW_SORT:
					{
						CheckMenuItem(GetMenu(hWnd), ID_VIEW_SORT, MF_CHECKED);
						ShowWindow(hSort, SW_SHOW);
					}
					break;

				case ID_FILE_OPEN:
					{
						WCHAR _dumpFileName[1024] = {0};
						OPENFILENAME ofln;
						memset(&ofln, 0, sizeof(OPENFILENAME));
						ofln.lStructSize = sizeof(OPENFILENAME);
						ofln.hwndOwner = hWndParent;
						ofln.lpstrFile = _dumpFileName;
						ofln.nMaxFile = sizeof(_dumpFileName)/2;
						ofln.lpstrFilter = L"GDIDump\0*.gdidmp\0All\0*.*\0";
						ofln.nFilterIndex = 1;
						ofln.lpstrFileTitle = NULL;
						ofln.nMaxFileTitle = 0;
						ofln.lpstrInitialDir = NULL;
						ofln.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

						GetOpenFileName(&ofln);

						// only refresh if new file actually selected
						if(lstrlen(_dumpFileName) != 0) {
							lstrcpyn(gDumpFileName, _dumpFileName, sizeof(gDumpFileName));
							SendMessage(hWnd, WM_COMMAND, ID_VIEW_REFRESH, 0);
						}
					}
					break;

				case ID_VIEW_REFRESH:
					{
						ShowWindow(pGdiTableVis->hWnd, SW_HIDE);
						ReadDumpFile(gDumpFileName, action, searchtype, searchhandle, searchpid);
						ApplySort();
						pGdiTableVis->SetTable(gdiCellVec);
						ShowWindow(pGdiTableVis->hWnd, SW_SHOW);
					}
					break;

				case IDM_EXIT:
					DestroyWindow(hWnd);
					break;

				default:
					return DefWindowProc(hWnd, message, wParam, lParam);
			}
			break;

		case WM_SYSCOMMAND:
			{
				wmId    = LOWORD(wParam);
				wmEvent = HIWORD(wParam);

				switch(wmId) {
					case SC_RESTORE:
						{
							// restore child Filter window if it was open before minimizing
							UINT res = GetMenuState(GetMenu(hWnd), ID_VIEW_FILTER, MF_BYCOMMAND);
							if(res & MF_CHECKED)
								ShowWindow(hFilter, SW_RESTORE);
							ShowWindow(hWndParent, SW_RESTORE);
						}
						break;

					default:
						return DefWindowProc(hWnd, message, wParam, lParam);
				}
			}
			break;

		case WM_SIZE:
			{
				GetClientRect(hWnd, &rect);
				int width = (rect.right-rect.left);
				int halfwidth = width/2;
				int height = (rect.bottom-rect.top);

				MoveWindow(hEdit, rect.right-450, 0, 450, height, FALSE);
				Edit_SetRect(hEdit, &rect);

				if(pGdiTableVis) {
					MoveWindow(pGdiTableVis->hWnd, 0,0, width-450, height, TRUE);
				}
			}
			break;

		case WM_CTLCOLOREDIT:
			{
				HDC hdc = (HDC)wParam;
				SetTextColor(hdc, COLORREF(RGB(255,255,255)));
				SetBkColor(hdc, RGB(0,0,0));
				return (LRESULT)GetStockObject(BLACK_BRUSH);
			}

		case WM_CTLCOLORSTATIC:
			{
				HDC hdc = (HDC)wParam;
				SetTextColor(hdc, COLORREF(RGB(255,255,255)));
				SetBkColor(hdc, RGB(0,0,0));
				return (LRESULT)GetStockObject(BLACK_BRUSH);
			}

		case WM_PAINT:
			{
				hdc = BeginPaint(hWnd, &ps);
				EndPaint(hWnd, &ps);
			}
			break;

		case WM_DESTROY:
			PostQuitMessage(0);
			break;

		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
