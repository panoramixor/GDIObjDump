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
#include "GdiTableVis.h"
#include <Windowsx.h>
#include <fstream>

GdiTableVis *pThis;			// ugly HACK? sue me

extern HWND hWndParent;
extern void DumpBase(DWORD index);


LRESULT CALLBACK GdiTableVisWndProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	return pThis->WinProc(hWnd, Msg, wParam, lParam);
}

LRESULT CALLBACK GdiTableVis::WinProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	HDC         hDC;
    PAINTSTRUCT Ps;
	HBRUSH      tmpBrush;
	RECT rect = { 0 };

	switch(Msg)
	{
	case WM_CREATE:
		break;

	case WM_ERASEBKGND:
		{
			GetClientRect(hWnd, &rect);
			hDC = (HDC)wParam;
			tmpBrush = CreateSolidBrush(COLORREF(RGB(0,0,0)));
			FillRect(hDC, &rect, tmpBrush);
			DeleteObject(tmpBrush);
		}
		break;

	case WM_PAINT:
		{
			GetClientRect(hWnd, &rect);

			hDC = BeginPaint(hWnd, &Ps);
			if(gdiObjectsX64.size() > 0) 
			{
				for (std::vector<GDICELL_64>::iterator iter = gdiObjectsX64.begin(); iter != gdiObjectsX64.end(); ++iter)
				{
						DWORD index = (DWORD)(iter - gdiObjectsX64.begin());
						tmpBrush = CreateSolidBrush(GetCellColor(LOBYTE(iter->wType)));
						// get a RECT from table index
						RectFromIndex(hWnd, index, (DWORD)gdiObjectsX64.size(), &rect, 1);		
						FillRect(hDC, &rect, tmpBrush);
						DeleteObject(tmpBrush);
				}
			}
			EndPaint(hWnd, &Ps);
		}
		break;

	case WM_DESTROY:
		PostQuitMessage(int(lParam));
		break;

	case WM_MOUSEHOVER:
		break;

	case WM_MOUSELEAVE: // The mouse pointer has left our window. Deactivate the tooltip.
		SendMessage(hWndToolTip, TTM_TRACKACTIVATE, (WPARAM)FALSE, (LPARAM)&_toolInfo);
		bTrackingMouse = FALSE;
		ShowWindow(hWndToolTip, SW_HIDE);
		break;

	case WM_MOUSEMOVE:
		{
			static int oldX, oldY;
			int newX, newY;

			if (!bTrackingMouse)   {
				TrackMouse();
				// Activate the tooltip.
				SendMessage(hWndToolTip, TTM_TRACKACTIVATE, (WPARAM)TRUE, (LPARAM)&_toolInfo);
			}
    
			newX = GET_X_LPARAM(lParam);
			newY = GET_Y_LPARAM(lParam);

			// greedy update for tooltip
			if ((newX != oldX) || (newY != oldY))
			{
				DWORD index = CoordToIndex(hWnd, newX, newY, (DWORD)gdiObjectsX64.size());

				if((index > gdiObjectsX64.size()-1) || (gdiObjectsX64.size() == 0)) {
					ShowWindow(hWndToolTip, SW_HIDE);
					break;
				} else {
					ShowWindow(hWndToolTip, SW_SHOW);

					oldX = newX;
					oldY = newY;
            
					WCHAR coords[0x100];
					swprintf_s(coords, ARRAYSIZE(coords), L"%016I64X", gdiObjectsX64.at(index).pKernelAddress);

					_toolInfo.lpszText = coords;
					RECT _rect;
					GetGridRect(hWnd, (DWORD)gdiObjectsX64.size(), &_rect);
					_toolInfo.rect = _rect;
					SendMessage(hWndToolTip, TTM_SETTOOLINFO, 0, (LPARAM)&_toolInfo);

					POINT pt = { newX, newY }; 
					ClientToScreen(hWnd, &pt);
					SendMessage(hWndToolTip, TTM_TRACKPOSITION, 0, (LPARAM)MAKELONG(pt.x + 10, pt.y - 20));
				}
			}
		}
		break;

	case WM_LBUTTONDOWN:
		{
			POINT point;
			GetCursorPos(&point);
			ScreenToClient(hWnd, &point);
			DWORD index = 0;
			if(gdiObjectsX64.size() > 0) {
				index = CoordToIndex(hWnd, point.x, point.y, (DWORD)gdiObjectsX64.size());

				if(index > (DWORD)gdiObjectsX64.size()-1) 
					break;

				DumpBase(index);
			}

		}
		break;

	default:
		return DefWindowProc(hWnd, Msg, wParam, lParam);
	}
	return 0;
}

HWND GdiTableVis::CreateTrackingToolTip(int toolID, HWND hDlg, WCHAR* pText)
{
	HINSTANCE hInstance = GetModuleHandle(NULL);
    // Create a tooltip.
    HWND hwndTT = CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, 
                                 WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, 
                                 CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 
                                 hDlg, NULL, hInstance,NULL);

    if (!hwndTT)
    {
      return NULL;
    }

    // Set up the tool information. In this case, the "tool" is the entire parent window.
    _toolInfo.cbSize   = sizeof(TOOLINFO);
    _toolInfo.uFlags   = /*TTF_IDISHWND |*/ TTF_TRACK | TTF_ABSOLUTE;
    _toolInfo.hwnd     = hDlg;
    _toolInfo.hinst    = hInstance;
    _toolInfo.lpszText = pText;
    _toolInfo.uId      = (UINT_PTR)hDlg;
	RECT _rect;
	GetGridRect(hDlg, (DWORD)gdiObjectsX64.size(), &_rect);
	_toolInfo.rect = _rect;
    
    GetClientRect(hDlg, &_toolInfo.rect);

    // Associate the tooltip with the tool window.
    
    SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM) (LPTOOLINFO) &_toolInfo);	
    
    return hwndTT;
}


int GdiTableVis::WinMain()
{
	WNDCLASSEX  WndCls1;
	MSG         Msg;

	HINSTANCE hInstance = GetModuleHandle(NULL);

    WndCls1.cbSize        = sizeof(WndCls1);
    WndCls1.style         = CS_OWNDC | CS_VREDRAW | CS_HREDRAW;
    WndCls1.lpfnWndProc   = GdiTableVisWndProc;
    WndCls1.cbClsExtra    = 0;
    WndCls1.cbWndExtra    = 0;
	WndCls1.hInstance     = hInstance;
    WndCls1.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    WndCls1.hCursor       = LoadCursor(NULL, IDC_ARROW);
    WndCls1.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    WndCls1.lpszMenuName  = NULL;
    WndCls1.lpszClassName = L"GdiTableVis";
    WndCls1.hIconSm       = LoadIcon(hInstance, IDI_APPLICATION);
    RegisterClassEx(&WndCls1);

	RECT rect = {0};

	GetClientRect(hWndParent, &rect);
	int halfwidth = (rect.right-rect.left)/2;
	int height = (rect.bottom-rect.top);

    hWnd = CreateWindowEx(WS_EX_TOPMOST,
                   WndCls1.lpszClassName, L"GdiSharedHandleTable",
				   WS_CHILD | WS_VISIBLE ,
                   0, 0, halfwidth, height,
                   hWndParent, NULL, hInstance, NULL);

	hWndToolTip = CreateTrackingToolTip(0, hWnd, L"");

	int ret = 0;
	do {
		ret = GetMessage( &Msg, hWnd, 0, 0 );
		TranslateMessage(&Msg); 
		DispatchMessage(&Msg); 
	} while(ret > 0);
	return static_cast<int>(Msg.wParam);
}


GdiTableVis::GdiTableVis()
{
	gdiObjectsX64.clear();

	INITCOMMONCONTROLSEX icc;       
	icc.dwSize =    sizeof(INITCOMMONCONTROLSEX);
	icc.dwICC =     ICC_TAB_CLASSES ;        	//Load tab and ToolTip control classes
	InitCommonControlsEx(&icc);   

	pThis = this;
}

GdiTableVis::~GdiTableVis()
{
	pThis = 0;
	DestroyWindow(hWnd);
}