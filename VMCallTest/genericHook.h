#pragma once
namespace genericHook {
#pragma pack( push )
#pragma warning( push )
#pragma warning( disable:4200 )
#pragma pack( 1 )
	typedef struct {
		size_t rbp;
		size_t r15;
		size_t r14;
		size_t r13;
		size_t r12;
		size_t r11;
		size_t r10;
		size_t r9;
		size_t r8;
		size_t rsi;
		size_t rdi;
		size_t rdx;
		size_t rbx;
		size_t flags;
		size_t rax;
		size_t rcx;
		size_t rest_of_stack[]; //this will start from the return address if the function entry point is hooked
	} REGSTRUCT;
	typedef union {
		struct {
			float f1, f2, f3, f4;
	    } f;
		struct {
			double d1, d2;
		} d;
	} XMM_REG;
	typedef struct {
		XMM_REG xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
	} XMMREGSTRUCT;
#pragma warning( pop )
#pragma pack( pop )
	typedef void (*genericHookRoutine)(REGSTRUCT& registers);
	bool createGenericHook(void* addrtohook, genericHookRoutine subroutine);
	bool activateGenericHook(void* addrtohook);
	bool deactivateGenericHook(void* addrtohook);
	void captureXMMregs(XMMREGSTRUCT* regs);
	void restoreXMMregs(XMMREGSTRUCT* regs);
}