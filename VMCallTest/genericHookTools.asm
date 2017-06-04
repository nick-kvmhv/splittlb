PUBLIC captureXMMs
PUBLIC restoreXMMs
.CODE
ALIGN     8
captureXMMs PROC FRAME
.ENDPROLOG
movupd [rcx],xmm1
movupd [rcx+10h],xmm2
movupd [rcx+20h],xmm3
movupd [rcx+30h],xmm4
movupd [rcx+40h],xmm5
movupd [rcx+50h],xmm6
movupd [rcx+60h],xmm7
ret
captureXMMs ENDP
restoreXMMs PROC FRAME
.ENDPROLOG
movupd xmm1,[rcx]
movupd xmm2,[rcx+10h]
movupd xmm3,[rcx+20h]
movupd xmm4,[rcx+30h]
movupd xmm5,[rcx+40h]
movupd xmm6,[rcx+50h]
movupd xmm7,[rcx+60h]
ret
restoreXMMs ENDP
_TEXT ENDS
END