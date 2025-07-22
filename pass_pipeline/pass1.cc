#include <cstdlib>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instructions.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
class pass1 : public ModulePass {
public:
  static char ID;
  pass1() : ModulePass(ID) {}
  bool runOnModule(Module &M) override;
};
} // namespace
static void register_pass1(const PassManagerBuilder &,
                           legacy::PassManagerBase &PM) {
  PM.add(new pass1());
}

char pass1::ID = 0x1;

bool pass1::runOnModule(Module &M) {

  LLVMContext &llvm_context = M.getContext();
  IntegerType *i8_type = IntegerType::getInt8Ty(llvm_context);
  IntegerType *i32_type = IntegerType::getInt32Ty(llvm_context);
  IntegerType *i64_type = IntegerType::getInt64Ty(llvm_context);
  PointerType *p8_type = PointerType::get(i8_type, 0);
  PointerType *p64_type = PointerType::get(i64_type, 0);

  FunctionType *pass1function_t = FunctionType::get(i64_type, {}, false);

  FunctionCallee pass1function =
      M.getOrInsertFunction("function1", pass1function_t);

  for (Function &function : M) {
    if (function.isDeclaration() || function.getName().startswith("llvm") ||
        function.size() == 0) {
      errs() << "[*] skip function:" << function.getName() << "\n";
      continue;
    }
    for (BasicBlock &basic_block : function) {
      for (Instruction &instruction : make_early_inc_range(basic_block)) {
        if (auto *call_instruction = dyn_cast<CallInst>(&instruction)) {
          StringRef callee_name =
              call_instruction->getCalledFunction()->getName();
          if (callee_name == "add") {
            IRBuilder<> ir_builder(call_instruction);
            ir_builder.CreateCall(pass1function, {});
          }
        }
      }
    }
    /*
     * NOTE:Black list end, normal function of SUT should be marked
     */
  }
  return true;
}

static RegisterStandardPasses
    optx_definition_checker(PassManagerBuilder::EP_ModuleOptimizerEarly,
                            register_pass1);

static RegisterStandardPasses
    opt0_definition_checker(PassManagerBuilder::EP_EnabledOnOptLevel0,
                            register_pass1);
