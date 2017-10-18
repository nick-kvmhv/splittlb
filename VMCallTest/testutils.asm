PUBLIC getrip
PUBLIC getrsp
PUBLIC invalidopcode
PUBLIC callProcDumpHV
.CODE
ALIGN     8
getrip PROC FRAME
.ENDPROLOG
mov rax,[rsp]
ret
getrip ENDP
ALIGN     8

getrsp PROC FRAME
.ENDPROLOG
mov rax,rsp
ret
ALIGN     8
getrsp ENDP

ALIGN     8
invalidopcode PROC FRAME
.ENDPROLOG
db 0ffh
db 0ffh
db 0ffh
ret
ALIGN     8
invalidopcode ENDP

ALIGN     8
MAGIC_NUMBER:
dq 0B045EACDACD52E22h
ALIGN     8
callProcDumpHV PROC FRAME
push rbx
.ENDPROLOG
mov rax,2
mov rdx,QWORD PTR [MAGIC_NUMBER]
mov rcx,1001h
vmcall
mov rax,rcx
pop rbx
ret
callProcDumpHV ENDP
ALIGN     8

_TEXT ENDS
END