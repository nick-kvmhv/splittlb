;PUBLIC genericHookDispatch
PUBLIC genericHookDispatchBody
PUBLIC handlerAddress
PUBLIC jumpOutAddress
PUBLIC genericHookDispatchEnd

.CODE
ALIGN     8
;genericHookDispatch PROC FRAME
;.ENDPROLOG
genericHookDispatchBody:
push rcx
push rax
pushfq
push rbx
push rdx
push rdi
push rsi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
push rbp
mov rcx, rsp
sub rsp,32
call qword ptr [handlerAddress]
add rsp,32
pop rbp
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rsi
pop rdi
pop rdx
pop rbx
popfq
pop rax
pop rcx
jmp qword ptr [jumpOutAddress]
ALIGN     8
;genericHookDispatch ENDP
handlerAddress: 
dq 0
jumpOutAddress: 
dq 0
ALIGN     8
genericHookDispatchEnd:
_TEXT ENDS
END