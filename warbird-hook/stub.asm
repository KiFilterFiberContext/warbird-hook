PUBLIC KiSwInterrupt

.code

KiSwInterrupt PROC
    int 20h
    ret
KiSwInterrupt ENDP

END