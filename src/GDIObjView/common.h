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

#ifndef __COMMON__
	#define __COMMON__


// search constants
#define SEARCH_HANDLE	0x0001
#define SEARCH_TYPE		SEARCH_HANDLE << 1
#define SEARCH_PID		SEARCH_HANDLE << 2
#define SHOW_UNUSED		SEARCH_HANDLE << 3

// TOOLTIP hacks for Vista+

#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif


void dprintf(char *format, ...);
void hexdump(unsigned char *buffer, unsigned long index, unsigned long width);

#include <windows.h>


#include <stdint.h> 

#include <typeinfo>
#include <map>

#include <iostream>
#include <vector>

#include <algorithm>

#define SIGN_EXTEND(_x_) (ULONG64)(LONG)(_x_)
#define ROUND_2_INT(f) ((int)(f >= 0.0 ? (f + 0.5) : (f - 0.5)))


// string and enum tricks

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,
#define GENERATE_STRINGW(STRING) L#STRING,


#define GDI_ENUM(GDI_OBJTYPE) \
        GDI_OBJTYPE(GDIObjType_DEF_TYPE)   \
        GDI_OBJTYPE(GDIObjType_DC_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED2_TYPE)   \
        GDI_OBJTYPE(GDIObjType_UNUSED3_TYPE)  \
        GDI_OBJTYPE(GDIObjType_RGN_TYPE)  \
        GDI_OBJTYPE(GDIObjType_SURF_TYPE)  \
        GDI_OBJTYPE(GDIObjType_CLIENTOBJ_TYPE)  \
        GDI_OBJTYPE(GDIObjType_PATH_TYPE)  \
        GDI_OBJTYPE(GDIObjType_PAL_TYPE)  \
        GDI_OBJTYPE(GDIObjType_ICMLCS_TYPE)  \
        GDI_OBJTYPE(GDIObjType_LFONT_TYPE)  \
        GDI_OBJTYPE(GDIObjType_RFONT_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED12_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED13_TYPE)  \
        GDI_OBJTYPE(GDIObjType_ICMCXF_TYPE)  \
        GDI_OBJTYPE(GDIObjType_SPRITE_TYPE)  \
        GDI_OBJTYPE(GDIObjType_BRUSH_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UMPD_TYPE)  \
        GDI_OBJTYPE(GDIObjType_HLSURF_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED19_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED20_TYPE)  \
        GDI_OBJTYPE(GDIObjType_META_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED22_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED23_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED24_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED25_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED26_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED27_TYPE)  \
        GDI_OBJTYPE(GDIObjType_DRVOBJ_TYPE)  \
        GDI_OBJTYPE(GDIObjType_UNUSED29_TYPE)  \
        GDI_OBJTYPE(GDIObjType_MAX_TYPE)  \


enum GDI_OBJTYPES {
    GDI_ENUM(GENERATE_ENUM)
};

static const char *GDI_OBJTYPE_NAME[] = {
    GDI_ENUM(GENERATE_STRING)
};

static const WCHAR *GDI_OBJTYPE_NAMEW[] = {
	GDI_ENUM(GENERATE_STRINGW)
};


#pragma pack(push)
#pragma pack(1)

// defines a GDI CELL
typedef struct
{
    ULONG pKernelAddress;
    USHORT wProcessId;
    USHORT wCount;
    USHORT wUpper;
    USHORT wType;
    ULONG pUserAddress;
} GDICELL_32;

// defines a GDI CELL for WOW64
typedef struct GDICELL_64
{
    PVOID64 pKernelAddress;
    USHORT wProcessId;
    USHORT wCount;
    USHORT wUpper;
    USHORT wType;
    PVOID64 pUserAddress;
	
	// translate to 64bit 
	void operator=(const GDICELL_32 &gdicell )
	{
		pKernelAddress = (PVOID64)gdicell.pKernelAddress;
		wProcessId = gdicell.wProcessId;
		wCount = gdicell.wCount;
		wType = gdicell.wType;
		wUpper = gdicell.wUpper;
		pUserAddress = (PVOID64)gdicell.pUserAddress;
	}

	// for std::sort use
    inline bool operator() (const GDICELL_64& struct1, const GDICELL_64& struct2)
    {
        return ((ULONG64)struct1.pKernelAddress < (ULONG64)struct2.pKernelAddress);
    }

	void dump()
	{
		dprintf("\nGDI_TABLE_ENTRY:\n");
		dprintf("\tpKernelAddress: %016I64x\n", pKernelAddress);
		dprintf("\twProcessId: %08lx\n", wProcessId);
		dprintf("\twCount: %04lx\n", wCount);
		dprintf("\twUpper: %04lx\n", wUpper);
		dprintf("\twType: %04lx (%s)\n", wType, GDI_OBJTYPE_NAME[LOBYTE(wType)]);
		dprintf("\tpUserAddress: %016I64x\n\n", pUserAddress);
	}

} GDICELL_64;


typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  ULONG32  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _BASEOBJECT32 // 5 elements, 0x10 bytes (sizeof)
 {
	ULONG32 hHmgr;
	ULONG32 ulShareCount;
	WORD cExclusiveLock;
	WORD BaseFlags;
	ULONG32 Tid;
 }BASEOBJECT32, *PBASEOBJECT32; 

typedef struct _BASEOBJECT64 
 {
	ULONG64 hHmgr;
	ULONG32 ulShareCount;
	WORD cExclusiveLock;
	WORD BaseFlags;
	ULONG64 Tid;

	void operator=(const BASEOBJECT32 &base )
	{
		hHmgr = base.hHmgr;
		ulShareCount = base.ulShareCount;
		cExclusiveLock = base.cExclusiveLock;
		BaseFlags = base.cExclusiveLock;
		Tid = base.Tid;
	}

	bool operator==(const _BASEOBJECT64 &base )
	{
		return ((hHmgr == base.hHmgr) && (Tid == base.Tid));
	}

	void dump()
	{
		dprintf("BASEOBJECT:\n");
		dprintf("\thHmgr: %08lx\n", hHmgr);
		dprintf("\tulShareCount: %08lx\n", ulShareCount);
		dprintf("\tcExclusiveLock: %04lx\n", cExclusiveLock);
		dprintf("\tBaseFlags: %04lx\n", BaseFlags);
		dprintf("\tTid: %016I64x\n\n", Tid);
	}

 }BASEOBJECT64, *PBASEOBJECT64; 


typedef struct _SURFOBJ32 {
	ULONG32 dhsurf;
	ULONG32  hsurf;
	ULONG32 dhpdev;
	ULONG32   hdev;
	SIZEL  sizlBitmap;
	ULONG  cjBits;
	ULONG32  pvBits;
	ULONG32  pvScan0;
	LONG   lDelta;
	ULONG  iUniq;
	ULONG  iBitmapFormat;
	USHORT iType;
	USHORT fjBitmap;
} SURFOBJ32 ;


typedef struct _SURFOBJ64 {
	ULONG64  dhsurf;
	ULONG64  hsurf;
	ULONG64  dhpdev;
	ULONG64  hdev;
	SIZEL  sizlBitmap;
	ULONG64  cjBits;
	ULONG64  pvBits;
	ULONG64  pvScan0;
	LONG32  lDelta;
	ULONG32  iUniq;
	ULONG32  iBitmapFormat;
	USHORT  iType;
	USHORT  fjBitmap;

	void operator=(const SURFOBJ32 &surf )
	{
		dhsurf = surf.dhsurf;
		hsurf = surf.hsurf;
		dhpdev = surf.dhpdev;
		hdev = surf.hdev;
		sizlBitmap = surf.sizlBitmap;
		cjBits = surf.cjBits;
		pvBits = surf.pvBits;
		pvScan0 = surf.pvScan0;
		lDelta = surf.lDelta;
		iUniq = surf.iUniq;
		iBitmapFormat = surf.iBitmapFormat;
		iType = surf.iType;
		fjBitmap = surf.fjBitmap;
	}

} SURFOBJ64;


// SURFOBJ constants
// fjBitmap flags
#define BMF_TOPDOWN    0x01
#define BMF_NOZEROINIT 0x02
#define BMF_DONTCACHE  0x04
#define BMF_USERMEM    0x08
#define BMF_KMSECTION  0x10
#define BMF_NOTSYSMEM  0x20
#define BMF_WINDOW_BLT 0x40
// iType
#define STYPE_BITMAP     0 /* DIBSECTION */
#define STYPE_DEVICE     1
#define STYPE_DEVBITMAP  3

typedef struct _COLORTRANSFORMOBJ32
{
	BASEOBJECT32 BaseObject;
	ULONG32     hColorTransform;
} GDICLRXFORM32;

typedef struct _COLORTRANSFORMOBJ64
{
	BASEOBJECT64 BaseObject;
	HANDLE     hColorTransform;

	void operator=(const GDICLRXFORM32 &ct )
	{
		BaseObject = ct.BaseObject;
		hColorTransform = (HANDLE)ct.hColorTransform;
	}

	void dump()
	{
		dprintf("GDICLRXFORM:\n");
		dprintf("\thColorTransform: %08lx\n\n", hColorTransform);
	}

} GDICLRXFORM64;



typedef struct _COLORSPACE32
{
  BASEOBJECT32  BaseObject;
  LOGCOLORSPACEW lcsColorSpace;
  DWORD dwFlags;
} COLORSPACE32;


typedef struct _COLORSPACE64
{
	BASEOBJECT64  BaseObject;
	LOGCOLORSPACEW lcsColorSpace;
	DWORD dwFlags;

	void operator=(const COLORSPACE32 &cs )
	{
		BaseObject = cs.BaseObject;
		lcsColorSpace = cs.lcsColorSpace;
		dwFlags = cs.dwFlags;
	}
	void dump()
	{
		dprintf("COLORSPACE:\n");
		dprintf("\tLOGCOLORSPACEW:");
		dprintf("\t\tlcsSignature: \'%c\',\'%c\',\'%c\',\'%c\'\n",	(lcsColorSpace.lcsSignature & 0xff), \
																	(lcsColorSpace.lcsSignature >> 8) & 0xff, \
																	(lcsColorSpace.lcsSignature >> 16) & 0xff, \
																	(lcsColorSpace.lcsSignature >> 24) & 0xff);

		dprintf("\t\tlcsVersion: %08lx\n", lcsColorSpace.lcsVersion);
		dprintf("\t\tlcsSize: %08lx\n", lcsColorSpace.lcsSize);
		dprintf("\t\tlcsCSType: \'%c\',\'%c\',\'%c\',\'%c\'\n",	(lcsColorSpace.lcsCSType & 0xff), \
																(lcsColorSpace.lcsCSType >> 8) & 0xff, \
																(lcsColorSpace.lcsCSType >> 16) & 0xff, \
																(lcsColorSpace.lcsCSType >> 24) & 0xff);

		dprintf("\t\tlcsIntent: %08lx\n", lcsColorSpace.lcsIntent);
		dprintf("\t\tlcsEndpoints: (R)%08I64lx (G)%08I64lx (B)%08I64lx\n",	lcsColorSpace.lcsEndpoints.ciexyzRed, \
																			lcsColorSpace.lcsEndpoints.ciexyzGreen, \
																			lcsColorSpace.lcsEndpoints.ciexyzBlue);

		dprintf("\t\tlcsGammaRed: %08lx\n", lcsColorSpace.lcsGammaRed);
		dprintf("\t\tlcsGammaGreen: %08lx\n", lcsColorSpace.lcsGammaGreen);
		dprintf("\t\tlcsGammaBlue: %08lx\n", lcsColorSpace.lcsGammaBlue);
		dprintf("\t\tlcsFilename: \"%S\"\n", lcsColorSpace.lcsFilename);
		dprintf("\tdwFlags: %08lx\n\n", dwFlags);
	}	
} COLORSPACE64;

enum _PALFLAGS
{
    PAL_INDEXED         = 0x00000001, // Indexed palette
    PAL_BITFIELDS       = 0x00000002, // Bit fields used for DIB, DIB section
    PAL_RGB             = 0x00000004, // Red, green, blue
    PAL_BGR             = 0x00000008, // Blue, green, red
    PAL_CMYK            = 0x00000010, // Cyan, magenta, yellow, black
    PAL_DC              = 0x00000100,
    PAL_FIXED           = 0x00000200, // Can't be changed
    PAL_FREE            = 0x00000400,
    PAL_MANAGED         = 0x00000800,
    PAL_NOSTATIC        = 0x00001000,
    PAL_MONOCHROME      = 0x00002000, // Two colors only
    PAL_BRUSHHACK       = 0x00004000,
    PAL_DIBSECTION      = 0x00008000, // Used for a DIB section
    PAL_NOSTATIC256     = 0x00010000,
    PAL_HT              = 0x00100000, // Halftone palette
    PAL_RGB16_555       = 0x00200000, // 16-bit RGB in 555 format
    PAL_RGB16_565       = 0x00400000, // 16-bit RGB in 565 format
    PAL_GAMMACORRECTION = 0x00800000, // Correct colors
};

typedef struct _PALETTE32
{
    BASEOBJECT32      BaseObject;    // 0x00

    FLONG           flPal;         // 0x10
    ULONG32           cEntries;      // 0x14
    ULONG           ulTime;        // 0x18
    ULONG32         hdcHead;       // 0x1c
    ULONG32        hSelected;     // 0x20, 
    ULONG           cRefhpal;      // 0x24
    ULONG           cRefRegular;   // 0x28
    ULONG32      ptransFore;    // 0x2c
    ULONG32      ptransCurrent; // 0x30
    ULONG32      ptransOld;     // 0x34
    ULONG           unk_038;       // 0x38
    ULONG32             pfnGetNearest; // 0x3c
    ULONG32             pfnGetMatch;   // 0x40
    ULONG           ulRGBTime;     // 0x44
    ULONG32       pRGBXlate;     // 0x48
    ULONG32    pFirstColor;  // 0x4c
    ULONG32 ppalThis;     // 0x50
    PALETTEENTRY    apalColors[1]; // 0x54
} PALETTE32;

typedef struct _PALETTE64
{
    BASEOBJECT64      BaseObject;    // 0x00

    FLONG           flPal;         // 0x18
    ULONG32           cEntries;      // 0x1C
    ULONG32           ulTime;        // 0x20 
    HDC             hdcHead;       // 0x24
    ULONG64        hSelected;     // 0x28, 
    ULONG64           cRefhpal;      // 0x30
    ULONG64          cRefRegular;   // 0x34
    ULONG64      ptransFore;    // 0x3c
    ULONG64      ptransCurrent; // 0x44
    ULONG64      ptransOld;     // 0x4C
    ULONG32           unk_038;       // 0x38
    ULONG64         pfnGetNearest; // 0x3c
    ULONG64			pfnGetMatch;   // 0x40
    ULONG64           ulRGBTime;     // 0x44
    ULONG64       pRGBXlate;     // 0x48
    PALETTEENTRY    *pFirstColor;  // 0x80
    struct _PALETTE *ppalThis;     // 0x88
    PALETTEENTRY    apalColors[3]; // 0x90

	void operator=(const PALETTE32 &pal )
	{
		BaseObject = pal.BaseObject;

		flPal = pal.flPal;
		cEntries = pal.cEntries;
		ulTime = pal.ulTime;
		hdcHead = (HDC)pal.hdcHead;
		hSelected = pal.hSelected;
		cRefhpal = pal.cRefhpal;
		cRefRegular = pal.cRefRegular;
		ptransFore = pal.ptransFore;
		ptransCurrent = pal.ptransCurrent;
		ptransOld = pal.ptransOld;
		unk_038 = pal.unk_038;
		pfnGetNearest = pal.pfnGetNearest;
		pfnGetMatch = pal.pfnGetMatch;
		ulRGBTime = pal.ulRGBTime;
		pRGBXlate = pal.pRGBXlate;
		pFirstColor = (PALETTEENTRY *)pal.pFirstColor;
		ppalThis = (_PALETTE *)pal.ppalThis;
		
		apalColors[0] = pal.apalColors[0];
		apalColors[1] = pal.apalColors[1];
		apalColors[2] = pal.apalColors[2];
	}

	void dump()
	{
		dprintf("PALETTE:\n");
		dprintf("\tflPal: %08lx (%s%s%s%s%s)\n", flPal, \
			(flPal & PAL_INDEXED) ? " PAL_INDEXED" : "", \
			(flPal & PAL_BITFIELDS) ? "PAL_BITFIELDS" : "", \
			(flPal & PAL_RGB) ? " PAL_RGB" : "", \
			(flPal & PAL_BGR) ? " PAL_BGR" : "", \
			(flPal & PAL_CMYK) ? " PAL_CMYK" : "", \
			(flPal & PAL_DC) ? " PAL_DC" : "", \
			(flPal & PAL_FIXED) ? " PAL_FIXED" : "", \
			(flPal & PAL_FREE) ? " PAL_FREE" : "", \
			(flPal & PAL_MANAGED) ? " PAL_MANAGED" : "", \
			(flPal & PAL_NOSTATIC) ? " PAL_NOSTATIC" : "", \
			(flPal & PAL_MONOCHROME) ? " PAL_MONOCHROME" : "", \
			(flPal & PAL_BRUSHHACK) ? " PAL_BRUSHHACK" : "", \
			(flPal & PAL_DIBSECTION) ? " PAL_DIBSECTION" : "", \
			(flPal & PAL_NOSTATIC256) ? " PAL_NOSTATIC256" : "", \
			(flPal & PAL_HT) ? " PAL_HT" : "", \
			(flPal & PAL_RGB16_555) ? " PAL_RGB16_555" : "", \
			(flPal & PAL_GAMMACORRECTION) ? " PAL_GAMMACORRECTION" : "");

		dprintf("\tcEntries: %08lx\n", cEntries);
		dprintf("\tulTime: %08lx\n", ulTime);
		dprintf("\thdcHead: %016I64x\n", hdcHead);
		dprintf("\thSelected: %016I64x\n", hSelected);
		dprintf("\tcRefhpal: %016I64x\n", cRefhpal);
		dprintf("\tcRefRegular: %016I64x\n", cRefRegular);

		dprintf("\tptransFore: %016I64x\n", ptransFore);
		dprintf("\tptransCurrent: %016I64x\n", ptransCurrent);
		dprintf("\tptransOld: %016I64x\n", ptransOld);
		dprintf("\tunk_038: %08lx\n", unk_038);

		dprintf("\tpfnGetNearest: %016I64x\n", pfnGetNearest);
		dprintf("\tpfnGetMatch: %016I64x\n", pfnGetMatch);

		dprintf("\tulRGBTime: %016I64x\n", ulRGBTime);
		dprintf("\tpRGBXlate: %016I64x\n", pRGBXlate);
		dprintf("\tpFirstColor: %016I64x\n", pFirstColor);
		dprintf("\tppalThis: %016I64x\n", ppalThis);

		dprintf("\tapalColors: [%08lx][%08lx][%08lx]\n\n",	*(DWORD *)&apalColors[0], \
																*(DWORD *)(&apalColors[1]), \
																*(DWORD *)(&apalColors[2]));

	}
} PALETTE64;


typedef struct _FONTOBJ {
	ULONG  iUniq;
	ULONG  iFace;
	ULONG  cxMax;
	FLONG  flFontType;
	ULONG_PTR  iTTUniq;
	ULONG_PTR  iFile;
	SIZE  sizLogResPpi;
	ULONG  ulStyleSize;
	PVOID  pvConsumer;
	PVOID  pvProducer;
} FONTOBJ;


typedef struct _LFONT32
{
   BASEOBJECT32    BaseObject;
   ULONG32        lft;
   FLONG         fl;
   ULONG32      Font;
   WCHAR         FullName[LF_FULLFACESIZE];
   WCHAR         Style[LF_FACESIZE];
   WCHAR         FaceName[LF_FACESIZE];
   DWORD         dwOffsetEndArray;
   ENUMLOGFONTEXDVW logfont;
   ULONG32 lock;
} LFONT32;


typedef struct _LFONT64
{
	BASEOBJECT64    BaseObject;
	ULONG32        lft;
	ULONG32         res1;
	ULONG32         res2;
	FLONG         fl;
	FONTOBJ      *Font;
	WCHAR         FullName[LF_FULLFACESIZE];
	WCHAR         Style[LF_FACESIZE];
	WCHAR         FaceName[LF_FACESIZE];
	DWORD         dwOffsetEndArray;
	ENUMLOGFONTEXDVW logfont;
	ULONG64 lock;

	void operator=(const LFONT32 &lfont )
	{
		BaseObject = lfont.BaseObject;
		lft = lfont.lft;
		fl = lfont.fl;
		Font = (FONTOBJ *)lfont.Font;
		
		memcpy(FullName, lfont.FullName, sizeof(lfont.FullName));
		memcpy(Style, lfont.Style, sizeof(lfont.Style));
		memcpy(FaceName, lfont.FaceName, sizeof(lfont.FaceName));

		dwOffsetEndArray = lfont.dwOffsetEndArray;
		logfont = lfont.logfont;
		lock = lfont.lock;
	}

} LFONT64;

typedef struct _LFONT_ACTUAL32
{
	BASEOBJECT32    BaseObject;
	ULONG32 unk0[3];
	DWORD flags;
	BYTE unk1[0x30];
	ULONG32 pCleanup;
	BYTE unk3[0x74];
	WCHAR FONTFAMILY[0x30];
	WCHAR FONTNAME[0x30];

} LFONT_ACTUAL32;


typedef struct _LFONT_ACTUAL64
{
	BASEOBJECT64    BaseObject;
	ULONG32 unk0[3];
	DWORD flags;
	BYTE unk1[0x30];
	ULONG64 pCleanup;
	BYTE unk3[0x70];
	WCHAR FONTFAMILY[0x30];
	WCHAR FONTNAME[0x30];

	void operator=(const LFONT_ACTUAL32 &lfont )
	{
		BaseObject = lfont.BaseObject;
		unk0[0] = lfont.unk0[0];
		unk0[1] = lfont.unk0[1];
		unk0[2] = lfont.unk0[2];
		flags = lfont.flags;
		memcpy(unk1, lfont.unk1, sizeof(unk1));
		memcpy(unk3, lfont.unk3, sizeof(unk3));
		pCleanup = (ULONG64)lfont.pCleanup;
		memcpy(FONTFAMILY, lfont.FONTFAMILY, sizeof(FONTFAMILY));
		memcpy(FONTNAME, lfont.FONTNAME, sizeof(FONTNAME));
	}

	void dump()
	{
	dprintf("LFONT:\n");
	dprintf("\tFlags: %08lx\n", flags);
	dprintf("\tpCleanup: %016I64x\n", pCleanup);
	dprintf("\tFamily: \"%S\"\n", FONTFAMILY);
	dprintf("\tName: \"%S\"\n\n", FONTNAME);

	}

} LFONT_ACTUAL64;


// SURFACES -------------------------------------------------------------------------------------

// string and enum tricks
#define BMF_ENUM(IBITMAPFORMAT) \
        IBITMAPFORMAT(BMF_INVALID)   \
        IBITMAPFORMAT(BMF_1BPP)   \
        IBITMAPFORMAT(BMF_4BPP)   \
        IBITMAPFORMAT(BMF_8BPP)   \
        IBITMAPFORMAT(BMF_16BPP)   \
        IBITMAPFORMAT(BMF_24BPP)   \
        IBITMAPFORMAT(BMF_32BPP)   \
        IBITMAPFORMAT(BMF_4RLE)   \
        IBITMAPFORMAT(BMF_8RLE)   \
        IBITMAPFORMAT(BMF_JPEG)   \
        IBITMAPFORMAT(BMF_PNG)   \

enum BMF_FORMAT {
    BMF_ENUM(GENERATE_ENUM)
};

static const char *BMF_FORMAT_NAME[] = {
    BMF_ENUM(GENERATE_STRING)
};

typedef struct _SURFACE32
{
    BASEOBJECT32  BaseObject;

    SURFOBJ32     SurfObj;
    //XDCOBJ *   pdcoAA;
    FLONG       flags;
    ULONG32		ppal; 

    ULONG32  hDDSurface;

    SIZEL       sizlDim;

    ULONG32         hdc;          // Doc in "Undocumented Windows", page 546, seems to be supported with XP.
    ULONG       cRef;
    ULONG32    hpalHint;

    /* For device-independent bitmaps: */
    ULONG32      hDIBSection;
    ULONG32      hSecure;
    DWORD       dwOffset;

} SURFACE32;


typedef struct _SURFACE64
{
    BASEOBJECT64  BaseObject;

    SURFOBJ64     SurfObj;
    //XDCOBJ *   pdcoAA;
    FLONG       flags;
    ULONG64		ppal; 

    HANDLE  hDDSurface;		

    SIZEL       sizlDim;

    HDC         hdc;          // Doc in "Undocumented Windows", page 546, seems to be supported with XP.
    ULONG       cRef;
    HPALETTE    hpalHint;

    /* For device-independent bitmaps: */
    HANDLE      hDIBSection;
    HANDLE      hSecure;
    DWORD       dwOffset;

	void operator=(const SURFACE32 &surf )
	{
		BaseObject = surf.BaseObject;
		SurfObj = surf.SurfObj;

		flags = surf.flags;

		ppal = surf.ppal;
		hDDSurface = (HANDLE)surf.hDDSurface;

		sizlDim = surf.sizlDim;

		hdc = (HDC)surf.hdc;
		cRef = surf.cRef;
		hpalHint = (HPALETTE)surf.hpalHint;
		hDIBSection = (HANDLE)surf.hDIBSection;
		hSecure = (HANDLE)surf.hSecure;
		dwOffset = surf.dwOffset;
	}
	void dump()
	{
		dprintf("SURFOBJ:\n" );
		dprintf("\tdhsurf:%016I64x\n", SurfObj.dhsurf);
		dprintf("\thsurf:%016I64x\n", SurfObj.hsurf);
		dprintf("\tdhpdev:%016I64x\n", SurfObj.dhpdev);
		dprintf("\thdev:%016I64x\n", SurfObj.hdev);
		dprintf("\tsizlBitmap: (X)%08lx (Y)%08lx\n", SurfObj.sizlBitmap.cx, SurfObj.sizlBitmap.cy);
		dprintf("\tcjBits: %016I64x\n", SurfObj.cjBits);
		dprintf("\tpvBits: %016I64x\n", SurfObj.pvBits);
		dprintf("\tpvScan0: %016I64x\n", SurfObj.pvScan0);
		dprintf("\tlDelta: %08lx\n", SurfObj.lDelta);
		dprintf("\tiUniq: %08lx\n", SurfObj.iUniq);
		dprintf("\tiBitmapFormat: %08lx (%s)\n", SurfObj.iBitmapFormat, BMF_FORMAT_NAME[SurfObj.iBitmapFormat]);

		dprintf("\tiType: %04lx (%s%s%s)\n", SurfObj.iType, \
			(SurfObj.iType == STYPE_BITMAP) ? "STYPE_BITMAP":"", \
			(SurfObj.iType == STYPE_DEVICE) ? "STYPE_DEVICE":"", \
			(SurfObj.iType == STYPE_DEVBITMAP) ? "STYPE_DEVBITMAP":"");
					
		dprintf("\tfjBitmap: %04lx (%s%s%s%s%s%s%s)\n\n", SurfObj.fjBitmap, \
			(SurfObj.fjBitmap & BMF_TOPDOWN) ? "BMF_TOPDOWN" : "", \
			(SurfObj.fjBitmap & BMF_NOZEROINIT) ? " BMF_NOZEROINIT" : "", \
			(SurfObj.fjBitmap & BMF_DONTCACHE) ? " BMF_DONTCACHE" : "", \
			(SurfObj.fjBitmap & BMF_USERMEM) ? " BMF_USERMEM" : "", \
			(SurfObj.fjBitmap & BMF_KMSECTION) ? " BMF_KMSECTION" : "", \
			(SurfObj.fjBitmap & BMF_NOTSYSMEM) ? " BMF_NOTSYSMEM" : "", \
			(SurfObj.fjBitmap & BMF_WINDOW_BLT) ? " BMF_WINDOW_BLT" : "");
	}

} SURFACE64;


typedef struct UNKNOWNOBJ32
{
	BASEOBJECT32  BaseObject;
	BYTE Buffer[0x040];
} UNKNOWNOBJ32;

typedef struct UNKNOWNOBJ64
{
	BASEOBJECT64  BaseObject;
	BYTE Buffer[0x100];

	void operator=(const UNKNOWNOBJ32 &other )
	{
		BaseObject = other.BaseObject;
		memcpy(Buffer , other.Buffer, sizeof(Buffer)); 
	}

	void dump()
	{
		hexdump(Buffer, sizeof(Buffer), 16);
	}

} UNKNOWNOBJ64;

#pragma pack(8)
typedef struct _UNICODE_STRING64 {
  USHORT Length;
  USHORT MaximumLength;
  ULONG64 Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;


#pragma pack(pop)


#define MAX_GDI_CELLS 0x10000
#define UNUSED_GDI_CELLS 10

#endif // __COMMON__