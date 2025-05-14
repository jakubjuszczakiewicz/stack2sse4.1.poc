BITS 64

SECTION .note.GNU-stack noalloc noexec nowrite progbits

SECTION .text
GLOBAL kit_sha512_iterate_asm
EXTERN _GLOBAL_OFFSET_TABLE_
EXTERN sha512_init_round_vector

%macro bswap_data_in 3
  mov rax, [rsi + %1]
  mov rdx, [rsi + %2]
  bswap rax
  bswap rdx
  pinsrq %3, rax, 0
  pinsrq %3, rdx, 1
%endmacro

; w[i]      -> %1 %2
; w[i - 2]  -> %3 %4
; w[i - 7]  -> %5 %6
; w[i - 15] -> %7 %8
; w[i - 16] -> %9 %10
%macro sha512_init_exp 10
  pextrq rax, %9, %10   ; rax -> w[i - 16]
  pextrq rdx, %7, %8    ; rdx -> w[i - 15]
  mov r9, rdx           ; r9  -> rdx
  mov r8, rdx           ; r8  -> rdx
  ror rdx, 1            ; rdx -> ror(rdx, 1)
  ror r8, 8             ; r8  -> ror(r8, 8)
  shr r9, 7             ; r9  -> shr(rdx, 7)
  xor rdx, r8           ; rdx -> xor(rdx, r8)
  xor rdx, r9           ; rdx -> xor(rdx, r9)
  add rax, rdx          ; rax -> rax + rdx
  pextrq rcx, %3, %4    ; rcx -> w[i - 2]
  mov rdx, rcx          ; rdx -> rcx
  mov r8, rcx           ; r8  -> rcx
  ror rdx, 19           ; rdx -> ror(rdx, 19)
  ror rcx, 61           ; rcx -> ror(rcx, 61)
  shr r8, 6             ; r8  -> shr(r8, 6)
  xor rdx, rcx          ; rdx -> xor(rdx, rcx)
  xor rdx, r8           ; rdx -> xor(rdx, r8)
  add rax, rdx          ; rax -> add(rax, rdx)
  pextrq rcx, %5, %6    ; rcx -> w[i - 7]
  add rax, rcx          ; rax -> rax + rcx
  pinsrq %1, rax, %2    ; w[i] -> rax
%endmacro

; tmp1 -> rax
; tmp2 -> edx
; a -> %1
; b -> %2
; c -> %3
; d -> %4
; e -> %5
; f -> %6
; g -> %7
; h -> %8
; w[n] -> %9 %10
; n -> %11
%macro sha512_step 11
  movq r8, %5           ; r8  -> e
  movq rax, %1          ; rax -> a
  movq rdx, %8          ; rdx -> h
  mov r9, r8            ; r9  -> r8 (e)
  mov r11, r8           ; r11 -> r8 (e)
  ror r8, 14            ; r8  -> ror(r8[e], 14)
  ror r9, 18            ; r9  -> ror(r9[e], 18)
  ror r11, 41           ; r11 -> ror(r11[e], 41)
  xor r8, r9            ; r8  -> xor(r8, r9)
  xor r8, r11           ; r8  -> xor(r8, r11)
  mov rax, rdx          ; rax -> rdx[h]
  add rax, r8           ; rax -> rax + r8
  movq r8, %5           ; r8  -> e
  movq r9, %6           ; r9  -> f
  and r9, r8            ; r9  -> and(r9[f], r8[e])
  not r8                ; r8  -> not(r8)
  movq r11, %7          ; r11 -> g
  and r8, r11           ; r8  -> and(r8, r11)
  xor r9, r8            ; r9  -> xor(r9, r8)
  add rax, r9           ; rax -> rax + r9
  add rax, [rel sha512_init_round_vector + 8 * %11] ; rax -> rax + vec[...
  pextrq r8, %9, %10    ; r8  -> w[n]
  add rax, r8           ; rax -> rax + r8[w[n]]

  movq rdx, %1          ; rdx -> a
  mov r8, rdx           ; r8  -> rdx[a]
  mov r9, rdx           ; r9  -> rdx[a]
  mov r11, rdx          ; r11 -> rdx[a]
  ror r8, 28            ; r8  -> ror(r8[rdx], 28)
  ror r9, 34            ; r9  -> ror(r9[rdx], 34)
  ror r11, 39           ; r11 -> ror(r11[rdx], 39)
  xor r8, r9            ; r8  -> xor(r8, r9)
  xor r8, r11           ; r8  -> xor(r8, r11)
  movq rcx, %2          ; rcx -> b
  movq rbx, %3          ; rbx -> c
  mov r9, rdx           ; r9  -> rdx
  and r9, rcx           ; r9  -> and(r9, rcx[b])
  and rdx, rbx          ; rdx -> and(rdx, rbx)
  xor rdx, r9           ; rdx -> xor(rdx, r9)
  and rcx, rbx          ; rcx -> and(rcx, rbx)
  xor rdx, rcx          ; rdx -> xor(rdx, rcx)
  add rdx, r8           ; rdx -> rdx + r8

  movq rbx, %4          ; rbx -> d
  add rbx, rax          ; rbx -> rbx + rax
  movq %4, rbx          ; d   -> rbx

  add rax, rdx          ; rax -> rax + rdx
  movq %8, rax          ; h   -> rax
%endmacro

kit_sha512_iterate_asm:
  push rbx
  bswap_data_in 0, 8, xmm0
  bswap_data_in 16, 24, xmm1
  bswap_data_in 32, 40, xmm2
  bswap_data_in 48, 56, xmm3
  bswap_data_in 64, 72, xmm4
  bswap_data_in 80, 88, xmm5
  bswap_data_in 96, 104, xmm6
  bswap_data_in 112, 120, xmm7

  movq mm0, [rdi]
  movq mm1, [rdi + 8]
  movq mm2, [rdi + 16]
  movq mm3, [rdi + 24]
  movq mm4, [rdi + 32]
  movq mm5, [rdi + 40]
  movq mm6, [rdi + 48]
  movq mm7, [rdi + 56]

  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm0, 0, 0
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm0, 1, 1
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm1, 0, 2
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm1, 1, 3
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm2, 0, 4
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm2, 1, 5
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm3, 0, 6
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm3, 1, 7
  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm4, 0, 8
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm4, 1, 9
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm5, 0, 10
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm5, 1, 11
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm6, 0, 12
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm6, 1, 13
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm7, 0, 14
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm7, 1, 15

  sha512_init_exp xmm8, 0, xmm7, 0, xmm4, 1, xmm0, 1, xmm0, 0
  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm8, 0, 16

  sha512_init_exp xmm8, 1, xmm7, 1, xmm5, 0, xmm1, 0, xmm0, 1
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm8, 1, 17

  sha512_init_exp xmm9, 0, xmm8, 0, xmm5, 1, xmm1, 1, xmm1, 0
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm9, 0, 18

  sha512_init_exp xmm9, 1, xmm8, 1, xmm6, 0, xmm2, 0, xmm1, 1
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm9, 1, 19

  sha512_init_exp xmm10, 0, xmm9, 0, xmm6, 1, xmm2, 1, xmm2, 0
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm10, 0, 20

  sha512_init_exp xmm10, 1, xmm9, 1, xmm7, 0, xmm3, 0, xmm2, 1
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm10, 1, 21

  sha512_init_exp xmm11, 0, xmm10, 0, xmm7, 1, xmm3, 1, xmm3, 0
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm11, 0, 22

  sha512_init_exp xmm11, 1, xmm10, 1, xmm8, 0, xmm4, 0, xmm3, 1
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm11, 1, 23

  sha512_init_exp xmm12, 0, xmm11, 0, xmm8, 1, xmm4, 1, xmm4, 0
  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm12, 0, 24

  sha512_init_exp xmm12, 1, xmm11, 1, xmm9, 0, xmm5, 0, xmm4, 1
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm12, 1, 25

  sha512_init_exp xmm13, 0, xmm12, 0, xmm9, 1, xmm5, 1, xmm5, 0
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm13, 0, 26

  sha512_init_exp xmm13, 1, xmm12, 1, xmm10, 0, xmm6, 0, xmm5, 1
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm13, 1, 27

  sha512_init_exp xmm14, 0, xmm13, 0, xmm10, 1, xmm6, 1, xmm6, 0
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm14, 0, 28

  sha512_init_exp xmm14, 1, xmm13, 1, xmm11, 0, xmm7, 0, xmm6, 1
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm14, 1, 29

  sha512_init_exp xmm15, 0, xmm14, 0, xmm11, 1, xmm7, 1, xmm7, 0
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm15, 0, 30

  sha512_init_exp xmm15, 1, xmm14, 1, xmm12, 0, xmm8, 0, xmm7, 1
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm15, 1, 31

  sha512_init_exp xmm0, 0, xmm15, 0, xmm12, 1, xmm8, 1, xmm8, 0
  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm0, 0, 32

  sha512_init_exp xmm0, 1, xmm15, 1, xmm13, 0, xmm9, 0, xmm8, 1
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm0, 1, 33

  sha512_init_exp xmm1, 0, xmm0, 0, xmm13, 1, xmm9, 1, xmm9, 0
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm1, 0, 34

  sha512_init_exp xmm1, 1, xmm0, 1, xmm14, 0, xmm10, 0, xmm9, 1
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm1, 1, 35

  sha512_init_exp xmm2, 0, xmm1, 0, xmm14, 1, xmm10, 1, xmm10, 0
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm2, 0, 36

  sha512_init_exp xmm2, 1, xmm1, 1, xmm15, 0, xmm11, 0, xmm10, 1
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm2, 1, 37

  sha512_init_exp xmm3, 0, xmm2, 0, xmm15, 1, xmm11, 1, xmm11, 0
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm3, 0, 38

  sha512_init_exp xmm3, 1, xmm2, 1, xmm0, 0, xmm12, 0, xmm11, 1
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm3, 1, 39

  sha512_init_exp xmm4, 0, xmm3, 0, xmm0, 1, xmm12, 1, xmm12, 0
  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm4, 0, 40

  sha512_init_exp xmm4, 1, xmm3, 1, xmm1, 0, xmm13, 0, xmm12, 1
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm4, 1, 41

  sha512_init_exp xmm5, 0, xmm4, 0, xmm1, 1, xmm13, 1, xmm13, 0
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm5, 0, 42

  sha512_init_exp xmm5, 1, xmm4, 1, xmm2, 0, xmm14, 0, xmm13, 1
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm5, 1, 43

  sha512_init_exp xmm6, 0, xmm5, 0, xmm2, 1, xmm14, 1, xmm14, 0
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm6, 0, 44

  sha512_init_exp xmm6, 1, xmm5, 1, xmm3, 0, xmm15, 0, xmm14, 1
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm6, 1, 45

  sha512_init_exp xmm7, 0, xmm6, 0, xmm3, 1, xmm15, 1, xmm15, 0
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm7, 0, 46

  sha512_init_exp xmm7, 1, xmm6, 1, xmm4, 0, xmm0, 0, xmm15, 1
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm7, 1, 47

  sha512_init_exp xmm8, 0, xmm7, 0, xmm4, 1, xmm0, 1, xmm0, 0
  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm8, 0, 48

  sha512_init_exp xmm8, 1, xmm7, 1, xmm5, 0, xmm1, 0, xmm0, 1
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm8, 1, 49

  sha512_init_exp xmm9, 0, xmm8, 0, xmm5, 1, xmm1, 1, xmm1, 0
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm9, 0, 50

  sha512_init_exp xmm9, 1, xmm8, 1, xmm6, 0, xmm2, 0, xmm1, 1
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm9, 1, 51

  sha512_init_exp xmm10, 0, xmm9, 0, xmm6, 1, xmm2, 1, xmm2, 0
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm10, 0, 52

  sha512_init_exp xmm10, 1, xmm9, 1, xmm7, 0, xmm3, 0, xmm2, 1
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm10, 1, 53

  sha512_init_exp xmm11, 0, xmm10, 0, xmm7, 1, xmm3, 1, xmm3, 0
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm11, 0, 54

  sha512_init_exp xmm11, 1, xmm10, 1, xmm8, 0, xmm4, 0, xmm3, 1
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm11, 1, 55

  sha512_init_exp xmm12, 0, xmm11, 0, xmm8, 1, xmm4, 1, xmm4, 0
  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm12, 0, 56

  sha512_init_exp xmm12, 1, xmm11, 1, xmm9, 0, xmm5, 0, xmm4, 1
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm12, 1, 57

  sha512_init_exp xmm13, 0, xmm12, 0, xmm9, 1, xmm5, 1, xmm5, 0
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm13, 0, 58

  sha512_init_exp xmm13, 1, xmm12, 1, xmm10, 0, xmm6, 0, xmm5, 1
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm13, 1, 59

  sha512_init_exp xmm14, 0, xmm13, 0, xmm10, 1, xmm6, 1, xmm6, 0
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm14, 0, 60

  sha512_init_exp xmm14, 1, xmm13, 1, xmm11, 0, xmm7, 0, xmm6, 1
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm14, 1, 61

  sha512_init_exp xmm15, 0, xmm14, 0, xmm11, 1, xmm7, 1, xmm7, 0
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm15, 0, 62

  sha512_init_exp xmm15, 1, xmm14, 1, xmm12, 0, xmm8, 0, xmm7, 1
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm15, 1, 63

  sha512_init_exp xmm0, 0, xmm15, 0, xmm12, 1, xmm8, 1, xmm8, 0
  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm0, 0, 64

  sha512_init_exp xmm0, 1, xmm15, 1, xmm13, 0, xmm9, 0, xmm8, 1
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm0, 1, 65

  sha512_init_exp xmm1, 0, xmm0, 0, xmm13, 1, xmm9, 1, xmm9, 0
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm1, 0, 66

  sha512_init_exp xmm1, 1, xmm0, 1, xmm14, 0, xmm10, 0, xmm9, 1
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm1, 1, 67

  sha512_init_exp xmm2, 0, xmm1, 0, xmm14, 1, xmm10, 1, xmm10, 0
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm2, 0, 68

  sha512_init_exp xmm2, 1, xmm1, 1, xmm15, 0, xmm11, 0, xmm10, 1
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm2, 1, 69

  sha512_init_exp xmm3, 0, xmm2, 0, xmm15, 1, xmm11, 1, xmm11, 0
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm3, 0, 70

  sha512_init_exp xmm3, 1, xmm2, 1, xmm0, 0, xmm12, 0, xmm11, 1
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm3, 1, 71

  sha512_init_exp xmm4, 0, xmm3, 0, xmm0, 1, xmm12, 1, xmm12, 0
  sha512_step mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7, xmm4, 0, 72

  sha512_init_exp xmm4, 1, xmm3, 1, xmm1, 0, xmm13, 0, xmm12, 1
  sha512_step mm7, mm0, mm1, mm2, mm3, mm4, mm5, mm6, xmm4, 1, 73

  sha512_init_exp xmm5, 0, xmm4, 0, xmm1, 1, xmm13, 1, xmm13, 0
  sha512_step mm6, mm7, mm0, mm1, mm2, mm3, mm4, mm5, xmm5, 0, 74

  sha512_init_exp xmm5, 1, xmm4, 1, xmm2, 0, xmm14, 0, xmm13, 1
  sha512_step mm5, mm6, mm7, mm0, mm1, mm2, mm3, mm4, xmm5, 1, 75

  sha512_init_exp xmm6, 0, xmm5, 0, xmm2, 1, xmm14, 1, xmm14, 0
  sha512_step mm4, mm5, mm6, mm7, mm0, mm1, mm2, mm3, xmm6, 0, 76

  sha512_init_exp xmm6, 1, xmm5, 1, xmm3, 0, xmm15, 0, xmm14, 1
  sha512_step mm3, mm4, mm5, mm6, mm7, mm0, mm1, mm2, xmm6, 1, 77

  sha512_init_exp xmm7, 0, xmm6, 0, xmm3, 1, xmm15, 1, xmm15, 0
  sha512_step mm2, mm3, mm4, mm5, mm6, mm7, mm0, mm1, xmm7, 0, 78

  sha512_init_exp xmm7, 1, xmm6, 1, xmm4, 0, xmm0, 0, xmm15, 1
  sha512_step mm1, mm2, mm3, mm4, mm5, mm6, mm7, mm0, xmm7, 1, 79

  movq rax, mm0
  movq rbx, mm1
  movq rcx, mm2
  movq rdx, mm3
  add [rdi], rax
  add [rdi + 8], rbx
  add [rdi + 16], rcx
  add [rdi + 24], rdx

  movq rax, mm4
  movq rbx, mm5
  movq rcx, mm6
  movq rdx, mm7
  add [rdi + 32], rax
  add [rdi + 40], rbx
  add [rdi + 48], rcx
  add [rdi + 56], rdx

  emms
  pop rbx
  ret


