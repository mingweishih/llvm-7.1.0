; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple x86_64-unknown-linux-gnu < %s | FileCheck %s

define void @main() {
; CHECK-LABEL: main:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    subq $424, %rsp # imm = 0x1A8
; CHECK-NEXT:    .cfi_def_cfa_offset 432
; CHECK-NEXT:    leaq {{[0-9]+}}(%rsp), %rdi
; CHECK-NEXT:    xorl %esi, %esi
; CHECK-NEXT:    movl $400, %edx # imm = 0x190
; CHECK-NEXT:    callq memset
; CHECK-NEXT:    movl {{[0-9]+}}(%rsp), %eax
; CHECK-NEXT:    movl (%rax), %ecx
; CHECK-NEXT:    addl 0, %eax
; CHECK-NEXT:    addl %ecx, %eax
; CHECK-NEXT:    addl %ecx, %eax
; CHECK-NEXT:    addl {{[0-9]+}}(%rsp), %eax
; CHECK-NEXT:    movl %eax, {{[0-9]+}}(%rsp)
; CHECK-NEXT:    movl {{[0-9]+}}(%rsp), %eax
; CHECK-NEXT:    movl %eax, %ecx
; CHECK-NEXT:    imull %eax, %ecx
; CHECK-NEXT:    subl %ecx, %eax
; CHECK-NEXT:    movl %eax, (%rax)
entry:
  %k = alloca i32, align 4
  %m = alloca i32, align 4
  %a = alloca [100 x i32], align 16
  %0 = bitcast [100 x i32]* %a to i8*
  call void @llvm.memset.p0i8.i64(i8* nonnull align 16 %0, i8 0, i64 400, i1 false)
  %arrayidx = getelementptr inbounds [100 x i32], [100 x i32]* %a, i64 0, i64 34
  %add = load i32, i32* %k
  %1 = load i32, i32* null
  %2 = load i32, i32* undef
  %3 = load i32, i32* undef
  %4 = load i32, i32* %arrayidx
  %5 = load i32, i32* undef
  %6 = load i32, i32* undef
  %7 = load i32, i32* undef
  %8 = load i32, i32* undef
  %9 = load i32, i32* undef
  %10 = load i32, i32* undef
  %11 = load i32, i32* undef
  %12 = load i32, i32* undef
  %13 = load i32, i32* undef
  %14 = load i32, i32* undef
  %15 = load i32, i32* undef
  %16 = load i32, i32* undef
  %add.1 = add i32 %add, %1
  %add.2 = add i32 %add.1, %2
  %add.3 = add i32 %add.2, %3
  %add.4 = add i32 %add.3, %4
  store i32 %add.4, i32* %k
  %17 = load i32, i32* %m
  %mul = mul i32 %17, %17
  %sub = sub i32 %17, %mul
  store i32 %sub, i32* undef
  unreachable
}

declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #0

attributes #0 = { argmemonly nounwind }
