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

#ifndef __TableGridView__
	#define __TableGridView__

#include <windows.h>
#include <vector>
#include "common.h"
#include <CommCtrl.h>


class TableGridView
{
	public:

		TOOLINFO _toolInfo;

		HWND hWndToolTip;
		HWND hWnd;

		BOOL bTrackingMouse;

		std::vector<GDICELL_64> gdiObjectsX64;
		std::vector<GDICELL_64> gdiObjectsOrdered;

//		int totalcellwidth;
		//int totalcellheight;

		virtual void SetTable(std::vector<GDICELL_64> &vec)
		{
			gdiObjectsX64 = vec;
			gdiObjectsOrdered = vec;
			std::sort(gdiObjectsOrdered.begin(), gdiObjectsOrdered.end(), GDICELL_64());
			SetWindowPos(hWnd, HWND_NOTOPMOST,0,0,0,0, SWP_NOMOVE |SWP_NOSIZE|SWP_SHOWWINDOW);
		}

		void GetGridRect(HWND hWnd, DWORD totalcells, RECT *rect)
		{
			if(!totalcells)
				return;

			DWORD cellgrid = ROUND_2_INT(sqrt(totalcells));
			RECT _rect;
			GetClientRect(hWnd, &_rect);
			DWORD cellstrideW = ROUND_2_INT((_rect.right-_rect.left)/cellgrid);
			DWORD cellstrideH = ROUND_2_INT((_rect.bottom-_rect.top)/cellgrid);
			rect->left = 0;
			rect->top = 0;
			rect->right = cellstrideW*cellgrid;
			rect->bottom = cellstrideH*cellgrid;
		}

		// returns a rect for a given gdiObjectsX64 table index
		DWORD RectFromIndex(HWND hWnd, DWORD index, DWORD totalcells, RECT *rect, DWORD border)
		{
			if(!totalcells)
				return 0;

			DWORD cellgrid = ROUND_2_INT(sqrt(totalcells));
			RECT _rect = {0};
			GetClientRect(hWnd, &_rect);

			DWORD cellstrideW = ROUND_2_INT((_rect.right-_rect.left)/cellgrid);
			DWORD cellstrideH = ROUND_2_INT((_rect.bottom-_rect.top)/cellgrid);

			int x = (index%cellgrid)*cellstrideW;
			int y = (index/cellgrid)*cellstrideH;

			rect->left = x;
			rect->top = y;
			rect->bottom = y+cellstrideH-border;
			rect->right = x+cellstrideW-border;

			return 0;
		}

		// cell color scheme
		COLORREF GetCellColor(BYTE wType)
		{
			COLORREF _COLORSCHEME[] = {	
				RGB(0x00,0x0F,0x5C), 
			//	RGB(0x08,0x17,0x61), 
				RGB(0x11,0x1F,0x67), 
			//	RGB(0x1A,0x27,0x6C), 
				RGB(0x23,0x30,0x72), 
				RGB(0x2B,0x38,0x78), 
				RGB(0x34,0x40,0x7D), 
				RGB(0x3D,0x48,0x83), 
				RGB(0x46,0x51,0x88), 
				RGB(0x4F,0x59,0x8E), 
				RGB(0x57,0x61,0x94), 
				RGB(0x60,0x6A,0x99), 
				RGB(0x69,0x72,0x9F), 
				RGB(0x72,0x7A,0xA5), 
				RGB(0x7B,0x82,0xAA), 
				RGB(0x83,0x8B,0xB0), 
				RGB(0x8C,0x93,0xB5), 
				RGB(0x95,0x9B,0xBB), 
				RGB(0x9E,0xA3,0xC1), 
				RGB(0xA7,0xAC,0xC6), 
				RGB(0xAF,0xB4,0xCC), 
				RGB(0xB8,0xBC,0xD2), 
				RGB(0xC1,0xC5,0xD7), 
				RGB(0xCA,0xCD,0xDD), 
				RGB(0xD3,0xD5,0xE2), 
				RGB(0xDB,0xDD,0xE8), 
				RGB(0xE4,0xE6,0xEE), 
				RGB(0xED,0xEE,0xF3), 
				RGB(0xF6,0xF6,0xF9), 
				RGB(0xFE,0xFF,0xFF), 
			};

			if(wType == GDIObjType_MAX_TYPE) {
				return COLORREF(RGB(255, 0, 0));
			}

			COLORREF res = wType ? _COLORSCHEME[wType%(sizeof(_COLORSCHEME)/4)] : 0;
			return res;
		}

		// transforms from window coordinates to an index into gdiObjectsX64
		DWORD CoordToIndex(HWND hWnd, DWORD x, DWORD  y, DWORD totalcells)
		{
			if(!totalcells)
				return 0;

			DWORD cellgrid = ROUND_2_INT(sqrt(totalcells));

			RECT rect = {0};
			GetClientRect(hWnd, &rect);


			DWORD cellstrideW = ROUND_2_INT((rect.right-rect.left)/cellgrid);
			DWORD cellstrideH = ROUND_2_INT((rect.bottom-rect.top)/cellgrid);

			DWORD cY = y/cellstrideH;
			DWORD cX = x/cellstrideW;

			return cY*cellgrid+cX;
		}

		void TrackMouse()
		{
			TRACKMOUSEEVENT tme = { sizeof(TRACKMOUSEEVENT) };
			tme.hwndTrack       = hWnd;
			tme.dwFlags         = TME_LEAVE;
			TrackMouseEvent(&tme);

			bTrackingMouse = TRUE;
		}



		virtual int WinMain() = 0;
		virtual LRESULT CALLBACK WinProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) = 0;

		TableGridView()
		{
			hWnd = 0;
			bTrackingMouse = FALSE;
		}

};

#endif // __TableGridView__