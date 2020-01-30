#include "X86.h"
#include "X86InstrInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include <iostream>

using namespace llvm;

#define DEBUG_TYPE "x86-binary-analysis"

namespace {
class X86BinaryAnalysis : public MachineFunctionPass {
public:
  static char ID;

  X86BinaryAnalysis() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "X86 Binary Analysis"; }

  bool doInitialization(Module &M) override;
  bool runOnMachineFunction(MachineFunction &F) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    MachineFunctionPass::getAnalysisUsage(AU);
    AU.addRequired<MachineModuleInfo>();
    AU.addPreserved<MachineModuleInfo>();
  }

private:
  MachineModuleInfo *MMI;
  const TargetMachine *TM;
  const X86Subtarget *STI;
  const X86InstrInfo *TII;

  void debug_reg_alisas(unsigned);
  void debug_all_operators(const MachineInstr &MI);
};

} // end anonymous namespace

FunctionPass *llvm::createX86BinaryAnalysisPass() {
  return new X86BinaryAnalysis();
}

char X86BinaryAnalysis::ID = 0;

bool X86BinaryAnalysis::doInitialization(Module &M) {
  return false;
}

bool X86BinaryAnalysis::runOnMachineFunction(MachineFunction &MF) {
  for (auto &MBB : MF) {
    for (auto &MI : MBB) {
      if (!MI.isBranch() && !MI.isCall())
        continue;
      if (MI.getNumOperands() < 5 || MI.getOperand(0).isGlobal())
        continue;
      if (!MI.getOperand(0).isReg() || !MI.getOperand(1).isImm() && !MI.getOperand(2).isReg())
        continue;
      std::cerr << MF.getName().str() << ", BB " << MBB.getNumber() << " ";   
      debug_all_operators(MI);    
    }
  }
  return false;
}

// Debugging functions.

void X86BinaryAnalysis::debug_reg_alisas(unsigned reg) {
  switch (reg) {
  case X86::AL:
  case X86::AX:
  case X86::EAX:
  case X86::RAX:
    std::cerr << "RAX";
    break;
  case X86::BL:
  case X86::BX:
  case X86::EBX:
  case X86::RBX:
    std::cerr << "RBX";
    break;
  case X86::CL:
  case X86::CX:
  case X86::ECX:
  case X86::RCX:
    std::cerr << "RCX";
    break;
  case X86::DL:
  case X86::DX:
  case X86::EDX:
  case X86::RDX:
    std::cerr << "RDX";
    break;
  case X86::SIL:
  case X86::SI:
  case X86::ESI:
  case X86::RSI:
    std::cerr << "RSI";
    break;
  case X86::DIL:
  case X86::DI:
  case X86::EDI:
  case X86::RDI:
    std::cerr << "RDI";
    break;
  case X86::R8B:
  case X86::R8W:
  case X86::R8D:
  case X86::R8:
    std::cerr << "R8";
    break;
  case X86::R9B:
  case X86::R9W:
  case X86::R9D:
  case X86::R9:
    std::cerr << "R9";
    break;
  case X86::R10B:
  case X86::R10W:
  case X86::R10D:
  case X86::R10:
    std::cerr << "R10";
    break;
  case X86::R11B:
  case X86::R11W:
  case X86::R11D:
  case X86::R11:
    std::cerr << "R11";
    break;
  case X86::R12B:
  case X86::R12W:
  case X86::R12D:
  case X86::R12:
    std::cerr << "R13";
    break;
  case X86::R13B:
  case X86::R13W:
  case X86::R13D:
  case X86::R13:
    std::cerr << "R13";
    break;
  case X86::RBP:
  case X86::EBP:
    std::cerr << "RBP";
    break;
  case X86::RSP:
  case X86::ESP:
    std::cerr << "RSP";
    break;
  default:
    std::cerr << "UNKOWN";
  }
}

void X86BinaryAnalysis::debug_all_operators(const MachineInstr& MI) {
  std::cerr << "OP " << MI.getOpcode() << " ";
  for (auto &MO : MI.operands()) {
    switch (MO.getType()) {
    case MachineOperand::MO_Register:
      std::cerr << "REG[";
      debug_reg_alisas(MO.getReg());
      std::cerr << "] ";
      break;
    case MachineOperand::MO_Immediate:
      std::cerr << "IMM[" << MO.getImm() << "] ";
      break;
    case MachineOperand::MO_MachineBasicBlock:
      std::cerr << "MBB[" << MO.getMBB()->getNumber() << "] ";
      break;
    case MachineOperand::MO_GlobalAddress:
      std::cerr << "GV ";
      break;
    default:
      std::cerr << "Other type: " << MO.getType() << " ";
    }
  }
  std::cerr << "\n";
}
