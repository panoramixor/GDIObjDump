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

#ifndef __GdiTableVis__
	#define __GdiTableVis__

#include "TableGridView.h"

class GdiTableVis: public TableGridView
{
	public:

		int GdiTableVis::WinMain();
		HWND GdiTableVis::CreateTrackingToolTip(int toolID, HWND hDlg, WCHAR* pText);
		LRESULT CALLBACK WinProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
		GdiTableVis();
		~GdiTableVis();

};

#endif // __GdiTableVis__