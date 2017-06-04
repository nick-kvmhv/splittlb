PUBLIC checkhv
PUBLIC setDataPagehv
PUBLIC activatePagehv
PUBLIC deactivatePagehv
PUBLIC deactivateAllPageshv
PUBLIC isPageSplithv
PUBLIC writeCodePagehv

.CODE
ALIGN     8
checkhv PROC FRAME
.ENDPROLOG
push rbx
mov ax,0005h
vmcall
pop rbx
ret
ALIGN     8
checkhv ENDP
ALIGN     8

setDataPagehv PROC FRAME
;void* pageAddr, void* data
push rbx
.ENDPROLOG
mov rbx,rcx
; rdx should already have it
mov ax,0001h
vmcall
pop rbx
ret
ALIGN     8
setDataPagehv ENDP

activatePagehv PROC FRAME
;void* pageAddr
push rbx
.ENDPROLOG
mov rbx,rcx
mov ax,0002h
vmcall
pop rbx
ret
ALIGN     8
activatePagehv ENDP

writeCodePagehv PROC FRAME
;void* pageAddr
push rbx
.ENDPROLOG
;mov rcx,rcx
;mov rdx,rdx
;mov r8,r8
mov ax,0003h
vmcall
pop rbx
ret
ALIGN     8
writeCodePagehv ENDP



deactivatePagehv PROC FRAME
;void* pageAddr
push rbx
.ENDPROLOG
mov rbx,rcx
mov ax,0004h
vmcall
pop rbx
ret
ALIGN     8
deactivatePagehv ENDP

deactivateAllPageshv PROC FRAME
.ENDPROLOG
push rbx
mov ax,0006h
vmcall
pop rbx
ret
ALIGN     8
deactivateAllPageshv ENDP
ALIGN     8

isPageSplithv PROC FRAME
.ENDPROLOG
push rbx
mov ax,0007h
vmcall
pop rbx
ret
ALIGN     8
isPageSplithv ENDP
ALIGN     8

_TEXT ENDS
END
