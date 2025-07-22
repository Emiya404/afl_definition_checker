#include <cstdlib>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instructions.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>

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
#include "llvm/IR/Value.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
class afl_definition_checker : public ModulePass {
public:
  static char ID;
  afl_definition_checker() : ModulePass(ID) {}
  bool runOnModule(Module &M) override;
};
} // namespace

char afl_definition_checker::ID = 0x1;
static void register_definition_checker(const PassManagerBuilder &,
                                        legacy::PassManagerBase &PM) {
  PM.add(new afl_definition_checker());
}
bool afl_definition_checker::runOnModule(Module &M) {

  LLVMContext &llvm_context = M.getContext();
  IntegerType *i8_type = IntegerType::getInt8Ty(llvm_context);
  IntegerType *i32_type = IntegerType::getInt32Ty(llvm_context);
  IntegerType *i64_type = IntegerType::getInt64Ty(llvm_context);
  PointerType *p8_type = PointerType::get(i8_type, 0);
  PointerType *p64_type = PointerType::get(i64_type, 0);

  /*
   * NOTE:
   * for SUT info, we just take the function index argument to fill the fuction
   * bucket for state info, there are 4 conditions:
   * AFLNET: state changes at every network message sent.
   * Instrument should take message buffer pointer and length.
   * AFLNET_Legion: state also changes at every network sent. But
   * the ckecker should maintain a tree to get state different from AFLNET
   * STATEAFL: state changes at every memory record dump.
   * It is impossible to know accurate state while running. Take nothing.
   * NSFUZZ: state changes at every raise.
   * Instrument should take state_trace_map and hash it.
   */
  FunctionType *store_sutinfo_t = FunctionType::get(i64_type, i32_type, false);
  FunctionType *update_sutstate_packet_t =
      FunctionType::get(i64_type, {p8_type, i32_type}, false);
  FunctionType *update_sutstate_dump_t =
      FunctionType::get(i64_type, ArrayRef<Type *>(), false);
  FunctionType *connect_monitor_t =
      FunctionType::get(i32_type, ArrayRef<Type *>(), false);
  FunctionType *check_getenv_t =
      FunctionType::get(i32_type, {p8_type, p8_type}, false);
  FunctionType *check_shmat_t =
      FunctionType::get(i32_type, {i32_type, p8_type}, false);

  FunctionCallee store_sutinfo =
      M.getOrInsertFunction("store_sutinfo", store_sutinfo_t);
  FunctionCallee update_sutstate_packet =
      M.getOrInsertFunction("update_sutstate_packet", update_sutstate_packet_t);
  FunctionCallee update_sutstate_dump =
      M.getOrInsertFunction("update_sutstate_dump", update_sutstate_dump_t);
  FunctionCallee connect_monitor =
      M.getOrInsertFunction("connect_monitor", connect_monitor_t);
  FunctionCallee check_getenv =
      M.getOrInsertFunction("check_getenv", check_getenv_t);
  FunctionCallee check_shmat =
      M.getOrInsertFunction("check_shmat", check_shmat_t);

  GlobalVariable *memory_state_shm = new GlobalVariable(
      p8_type, false, GlobalVariable::ExternalLinkage, 0, "__mstate_shm_ptr");
  GlobalVariable *memory_state_shm_id = new GlobalVariable(
      i32_type, false, GlobalVariable::ExternalLinkage, 0, "__mstate_shm_id");
  /*
   * NOTE:
   * for each function in the target, we insert call instruction to mark the
   * function called. for each function in afl-based stateful fuzzing works,
   * we extract and update state seq.
   *
   */
  int counter = 0;
  char *function_list_dir = getenv("DEFINITION_CHECKER_LIST");
  int function_list_fd = 0;
  if (function_list_dir) {
    function_list_fd = open(function_list_dir, O_CREAT | O_RDWR, 0666);
    if (function_list_fd < 0) {
      perror("[*]open function list file failed");
    }
  }
  char buf[100];
  memset(buf, 0x0, 100);
  lseek(function_list_fd, 0, SEEK_SET);
  read(function_list_fd, buf, 100);
  counter = atoi(buf);

  for (Function &function : M) {
    if (function.isDeclaration() || function.getName().startswith("llvm") ||
        function.size() == 0) {
      errs() << "[*] skip function:" << function.getName() << "\n";
      continue;
    }
#ifdef PACKET_SEND_INSTRUMENT

    for (BasicBlock &basic_block : function) {
      for (Instruction &instruction : make_early_inc_range(basic_block)) {
        if (auto *call_instruction = dyn_cast<CallInst>(&instruction)) {
          StringRef callee_name =
              call_instruction->getCalledFunction()->getName();

#if (defined LIGHTFTP_SEND_INSTRUMENT) || (defined LIVE555_SEND_INSTRUMENT)
          if (callee_name == "send") {
            auto *send_buf = call_instruction->getArgOperand(1);
            auto *send_size = call_instruction->getArgOperand(2);
            update_sutstate_packet_args.push_back(send_buf);
            update_sutstate_packet_args.push_back(send_size);
            IRBuilder<> ir_builder(call_instruction);
            ir_builder.CreateCall(update_sutstate_packet,
                                  update_sutstate_packet_args, "result");
          }
#endif

#ifdef TINYFTPD_SEND_INSTRUMENT
          if (callee_name == "sendto") {
            auto *send_buf = call_instruction->getArgOperand(1);
            auto *send_size = call_instruction->getArgOperand(2);
            std::vector<Value *> update_sutstate_packet_args;
            update_sutstate_packet_args.push_back(send_buf);
            update_sutstate_packet_args.push_back(send_size);
            IRBuilder<> ir_builder(call_instruction);
            ir_builder.CreateCall(update_sutstate_packet,
                                  update_sutstate_packet_args, "result");
          }
#endif
#ifdef OPENSSL_SEND_INSTRUMENT
          if (callee_name == "sock_write") {
            auto *send_buf = call_instruction->getArgOperand(1);
            auto *send_size = call_instruction->getArgOperand(2);
            std::vector<Value *> update_sutstate_packet_args;
            update_sutstate_packet_args.push_back(send_buf);
            update_sutstate_packet_args.push_back(send_size);
            IRBuilder<> ir_builder(call_instruction);
            ir_builder.CreateCall(update_sutstate_packet,
                                  update_sutstate_packet_args, "result");
          }
#endif

#ifdef OPENSSH_SEND_INSTRUMENT
          if (callee_name == "ssh_packet_write_poll") {
            auto *ssh_struct = call_instruction->getArgOperand(0);
            auto *ssh_type = 0xf0000000;
            std::vector<Value *> update_sutstate_packet_args;
            update_sutstate_packet_args.push_back(ssh_struct);
            update_sutstate_packet_args.push_back(ssh_type);
            IRBuilder<> ir_builder(call_instruction);
            ir_builder.CreateCall(update_sutstate_packet,
                                  update_sutstate_packet_args, "result");
          }
#endif
        }
      }
    }
#endif

#ifdef MEMORY_STATE_INSTRUMENT
    for (BasicBlock &basic_block : function) {
      for (Instruction &instruction : basic_block) {
        if (auto *call_instruction = dyn_cast<CallInst>(&instruction)) {
          StringRef callee_name =
              call_instruction->getCalledFunction()->getName();
          if (callee_name == "compute_state_value") {
            auto *next_instruction = call_instruction->getNextNode();
            IRBuilder<> ir_builder(next_instruction);
            ir_builder.CreateCall(update_sutstate_dump, {}, "result");
          }
          if (callee_name == "raise") {
            IRBuilder<> ir_builder(call_instruction);
            ir_builder.CreateCall(update_sutstate_dump, {}, "result");
          }
          if (callee_name == "shmat") {
            auto *next_instruction = call_instruction->getNextNode();
            IRBuilder<> ir_builder(next_instruction);
            Value *shm_ptr = call_instruction->getReturnedArgOperand();
            Value *shm_id = call_instruction->getArgOperand(0);
            std::vector<Value *> check_shmat_args;
            check_shmat_args.push_back(shm_id);
            check_shmat_args.push_back(shm_ptr);
            ir_builder.CreateCall(check_shmat, check_shmat_args);
          }
          if (callee_name == "getenv") {
            IRBuilder<> ir_builder(call_instruction->getNextNode());
            Value *env_str = call_instruction->getArgOperand(0);
            Value *env_res = call_instruction->getReturnedArgOperand();
            std::vector<Value *> check_getenv_args;
            check_getenv_args.push_back(env_str);
            check_getenv_args.push_back(env_res);
            ir_builder.CreateCall(check_getenv, check_getenv_args);
          }
        }
      }
    }
#endif
    /*
     * NOTE:Black list end, normal function of SUT should be marked
     */
    BasicBlock &first_basicblock = function.getEntryBlock();
    IRBuilder<> ir_builder(&*first_basicblock.getFirstInsertionPt());

    StringRef func_name = function.getName();
    if (func_name == "main") {
      ir_builder.CreateCall(connect_monitor, {}, "connect_result");
    }

    ConstantInt *callee_code = ConstantInt::get(i32_type, counter);
    std::vector<Value *> store_sutinfo_args;
    store_sutinfo_args.push_back(callee_code);

    ir_builder.CreateCall(store_sutinfo, store_sutinfo_args);

    char function_list_record[100];
    memset(function_list_record, 0x0, 100);
    int function_list_record_len = sprintf(function_list_record, "%d", counter);
    lseek(function_list_fd, 0, SEEK_SET);
    if (function_list_fd) {
      write(function_list_fd, function_list_record, function_list_record_len);
    }
    counter++;
  }
  close(function_list_fd);
  return true;
}

static RegisterStandardPasses
    optx_definition_checker(PassManagerBuilder::EP_ModuleOptimizerEarly,
                            register_definition_checker);

static RegisterStandardPasses
    opt0_definition_checker(PassManagerBuilder::EP_EnabledOnOptLevel0,
                            register_definition_checker);
