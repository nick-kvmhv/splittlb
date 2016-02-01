// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN 

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <conio.h>
#include <set>
#include <map>
#include <MinHook.h>
#include "PatchManager.h"
#include "utils.h"
#include "DebugHelper.h"

//Blank out logging calls.
namespace pantheios {
	inline void log(...) {};
	const int error=0,informational=0,debug=0,warning=0;
	inline int integer(...) {return 0;};
	inline int pointer(...) {return 0;};
	inline int real(...) {return 0;};
	namespace fmt {
		const int fullHex =0,hex=0;
	}
}
