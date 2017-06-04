PUBLIC getrip
PUBLIC invalidopcode
.CODE
ALIGN     8
getrip PROC FRAME
.ENDPROLOG
mov rax,[rsp]
ret
ALIGN     8
getrip ENDP
ALIGN     8
.CODE
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

_TEXT ENDS
END