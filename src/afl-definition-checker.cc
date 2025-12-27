#include <cstdlib>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instructions.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
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

int bb_count_fd;
char *bb_count_fn;

int get_bb_count_file() {
  int r;
  char bb_count_file[0x100];
  if (!bb_count_fn) {
    char *home_env_dir = getenv("HOME");
    if (!home_env_dir) {
      errs() << "[!]not set env HOME\n";
      exit(1);
    }

    if (strlen(home_env_dir) > sizeof(bb_count_file) + 13) {
      errs() << "[!]too long HOME dir\n";
      exit(1);
    }

    memset(bb_count_file, 0x0, sizeof(bb_count_file));
    sprintf(bb_count_file, "%s/bb_count.txt", home_env_dir);
    errs() << bb_count_file << " " << strlen(bb_count_file) << "\n";
    bb_count_fn = (char *)malloc(strlen(bb_count_file) + 1);
    if (!bb_count_fn) {
      errs() << "[!]malloc bb file name failed\n";
      exit(1);
    }
    memset(bb_count_fn, 0x0, strlen(bb_count_file) + 1);
    strncpy(bb_count_fn, bb_count_file, strlen(bb_count_file));
  } else {
    memset(bb_count_file, 0x0, sizeof(bb_count_file));
    strncpy(bb_count_file, bb_count_fn, strlen(bb_count_file));
  }

  if (access(bb_count_file, R_OK | W_OK)) {
    errs() << "[!]cannot access the file\n";
    r = open(bb_count_file, O_RDWR | O_CREAT, 0666);
  } else {
    r = open(bb_count_file, O_RDWR);
  }
  if (r <= 0) {
    errs() << "[!]open failed the file\n";
    exit(1);
  }

  return r;
}

int read_bb_count_file(int fd) {

  int r;
  char bb_count[0x100];
  if (fd <= 0) {
    errs() << "[!]illegal fd\n";
    exit(1);
  }
  memset(bb_count, 0x0, sizeof(bb_count));
  lseek(fd, 0x0, SEEK_SET);
  r = read(fd, bb_count, sizeof(bb_count));
  if (r < 0) {
    errs() << "[!]read file err\n";
    exit(1);
  }

  return atoi(bb_count);
}

int write_bb_count_file(int fd, int count) {

  int r;
  char bb_count[0x100];
  if (fd <= 0) {
    errs() << "[!]illegal fd\n";
    exit(1);
  }

  memset(bb_count, 0x0, sizeof(bb_count));
  lseek(fd, 0x0, SEEK_SET);
  sprintf(bb_count, "%d", count);
  r = write(fd, bb_count, sizeof(bb_count));
  if (r < 0) {
    errs() << "[!] write file err\n";
    exit(1);
  }

  return r;
}

enum protocol { FTP, RTSP, DTLS, SSH, TLS };
char afl_definition_checker::ID = 0x1;
static void register_definition_checker(const PassManagerBuilder &,
                                        legacy::PassManagerBase &PM) {
  PM.add(new afl_definition_checker());
}
bool afl_definition_checker::runOnModule(Module &M) {

  errs() << "[*]afl-definition-checker successfully loaded on SUT\n";
  LLVMContext &llvm_context = M.getContext();
  IntegerType *i8_type = IntegerType::getInt8Ty(llvm_context);
  IntegerType *i32_type = IntegerType::getInt32Ty(llvm_context);
  IntegerType *i64_type = IntegerType::getInt64Ty(llvm_context);
  PointerType *p8_type = PointerType::get(i8_type, 0);
  PointerType *p64_type = PointerType::get(i64_type, 0);

  /*
   * NOTE:
   * for SUT info, we try to find AFL original instrument and take the basic
   * block hash for state info, there are 4 conditions: AFLNET: state changes at
   * every network message sent. Instrument should take message buffer pointer
   * and length. AFLNET_Legion: state also changes at every network sent. But
   * the ckecker should maintain a tree to get state different from AFLNET
   * STATEAFL: state changes at every memory record dump.
   * It is impossible to know accurate state while running. Take nothing.
   * NSFUZZ: state changes at every raise.
   * Instrument should take state_trace_map and hash it.
   */
  FunctionType *store_sutinfo_t = FunctionType::get(i64_type, i32_type, false);
  FunctionType *update_sutstate_packet_t =
      FunctionType::get(i64_type, {p8_type, i32_type, i32_type, i32_type}, false);
  FunctionType *update_sutstate_dump_t =
      FunctionType::get(i64_type, {i32_type}, false);
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
  FunctionCallee create_bucket =
      M.getOrInsertFunction("create_new_bucket", connect_monitor_t);

  GlobalVariable *memory_state_shm = new GlobalVariable(
      p8_type, false, GlobalVariable::ExternalLinkage, 0, "__mstate_shm_ptr");
  GlobalVariable *memory_state_shm_id = new GlobalVariable(
      i32_type, false, GlobalVariable::ExternalLinkage, 0, "__mstate_shm_id");

  /*
   * NOTE:
   * for fuzzing whose state-extraction function is in instrument, we should
   * also use this Pass to optimize object files in llvm_mode dir when compiling
   * afl-clang-fast(++) and test_instr, we do not instrument anything
   */
  if (M.getName().find("clang") != StringRef::npos ||
      M.getName().find("test_instr") != StringRef::npos) {
    return true;
  }
  /*
   * NOTE:
   * identify AFL branch coverage by find references of __afl_area_ptr
   * if the next instruction exists and is "XOR", found
   */
  int bb_count = 0;
  bb_count_fd = get_bb_count_file();
  bb_count = read_bb_count_file(bb_count_fd);
  //errs() << "bbcount " << bb_count << "\n";

  for (Function &F : M) {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
          auto *pBase = LI->getOperand(0);

          // check if afl instrument exists
          if (auto *GV = dyn_cast<GlobalVariable>(pBase)) {
            if (!(GV->getName().equals("__afl_area_ptr"))) {
              continue;
            }
            Instruction *TI = LI->getNextNode();

            bool isXor = false;
            if (TI->getOpcodeName()) {
              isXor = !strcmp(TI->getOpcodeName(), "xor");
            }
            if (TI && isXor) {
              Instruction *NI = TI->getNextNode();
              if (NI) {
                
                  IRBuilder<> IRB(NI);
                  std::vector<Value *> store_sutinfo_args;
                  ConstantInt *bb_count_arg =
                      ConstantInt::get(i32_type, bb_count);
                  store_sutinfo_args.push_back(bb_count_arg);
                  bb_count++;
                  IRB.CreateCall(store_sutinfo, store_sutinfo_args);
                
              }
            }
          }
        }
      }
    }
  }
  write_bb_count_file(bb_count_fd, bb_count);
  close(bb_count_fd);
  /*
   * NOTE:
   * next step, instrument to extract state info
   */
  for (Function &function : M) {
    if (function.isDeclaration() || function.getName().startswith("llvm") ||
        function.size() == 0) {
      //errs() << "[*] skip function:" << function.getName() << "\n";
      continue;
    }

    if (function.getName() == "main") {
      IRBuilder<> ir_builder(
          &*(function.getEntryBlock().getFirstInsertionPt()));
      ir_builder.CreateCall(connect_monitor, {}, "connect_result");
    }

#ifdef PACKET_SEND_INSTRUMENT

    for (BasicBlock &basic_block : function) {
      for (Instruction &instruction : basic_block) {
        if (auto *call_instruction = dyn_cast<CallInst>(&instruction)) {
          Value *CalledV = call_instruction->getCalledOperand();
          CalledV = CalledV->stripPointerCasts();
          if (auto *function_candidate = dyn_cast<Function>(CalledV)) {

            StringRef callee_name =
                function_candidate->getName();

#if (defined LIGHTFTP_SEND_INSTRUMENT) || (defined LIVE555_SEND_INSTRUMENT)
            if (callee_name == "send") {
              auto *send_buf = call_instruction->getArgOperand(1);
              auto *send_size = call_instruction->getArgOperand(2);
              std::vector<Value *> update_sutstate_packet_args;
              update_sutstate_packet_args.push_back(send_buf);
              update_sutstate_packet_args.push_back(send_size);
            #ifdef LIGHTFTP_SEND_INSTRUMENT
              ConstantInt *code = ConstantInt::get(i32_type, FTP);
            #else
              ConstantInt *code = ConstantInt::get(i32_type, RTSP);
            #endif
              update_sutstate_packet_args.push_back(code);
              ConstantInt *notcheck = ConstantInt::get(i32_type, 0x0);
              update_sutstate_packet_args.push_back(notcheck);
              IRBuilder<> ir_builder(call_instruction);
              ir_builder.CreateCall(update_sutstate_packet,
                                    update_sutstate_packet_args, "result");
            }
#endif

#ifdef TINYDTLS_SEND_INSTRUMENT
            if (callee_name == "sendto") {
              auto *send_buf = call_instruction->getArgOperand(1);
              auto *send_size = call_instruction->getArgOperand(2);
              ConstantInt *code = ConstantInt::get(i32_type, DTLS);
              std::vector<Value *> update_sutstate_packet_args;
              update_sutstate_packet_args.push_back(send_buf);
              update_sutstate_packet_args.push_back(send_size);
              update_sutstate_packet_args.push_back(code);
              ConstantInt *notcheck = ConstantInt::get(i32_type, 0x0);
              update_sutstate_packet_args.push_back(notcheck);
              IRBuilder<> ir_builder(call_instruction);
              ir_builder.CreateCall(update_sutstate_packet,
                                    update_sutstate_packet_args, "result");
            }
#endif

#ifdef OPENSSL_SEND_INSTRUMENT

#endif

#ifdef OPENSSH_SEND_INSTRUMENT
          if (callee_name == "write") {
              auto *send_buf = call_instruction->getArgOperand(1);
              auto *send_size = call_instruction->getArgOperand(2);
              ConstantInt *code = ConstantInt::get(i32_type, SSH);
              std::vector<Value *> update_sutstate_packet_args;
              update_sutstate_packet_args.push_back(send_buf);
              update_sutstate_packet_args.push_back(send_size);
              update_sutstate_packet_args.push_back(code);
              auto *checkfd = call_instruction->getArgOperand(0);
              update_sutstate_packet_args.push_back(checkfd);
              IRBuilder<> ir_builder(call_instruction);
              ir_builder.CreateCall(update_sutstate_packet,
                                    update_sutstate_packet_args, "result");
            }
#endif
        }
      }
    }
  }
#endif

#ifdef MEMORY_STATE_INSTRUMENT
  for (BasicBlock &basic_block : function) {
    for (Instruction &instruction : basic_block) {
      if (auto *call_instruction = dyn_cast<CallInst>(&instruction)) {
        Value *CalledV = call_instruction->getCalledOperand();
        CalledV = CalledV->stripPointerCasts();
        if (auto *function_candidate = dyn_cast<Function>(CalledV)) {
          StringRef callee_name = function_candidate->getName();

          if (callee_name == "compute_state_value") {
            auto *next_instruction = call_instruction->getNextNode();
            IRBuilder<> ir_builder(next_instruction);
            Value *state_code = call_instruction;
            std::vector<Value *> update_sutstate_dump_args;
            update_sutstate_dump_args.push_back(state_code);
            ir_builder.CreateCall(update_sutstate_dump,
                                  update_sutstate_dump_args, "result");
          }
          if (callee_name == "raise" &&
              function.getName().find("afl") == StringRef::npos) {
            IRBuilder<> ir_builder(call_instruction);
            ir_builder.CreateCall(create_bucket, {});
            ir_builder.CreateCall(update_sutstate_dump, {}, "result");
          }

          if (callee_name == "shmat") {
            auto *next_instruction = call_instruction->getNextNode();
            if (next_instruction != nullptr) {
              errs() << next_instruction << "\n";
            }
            IRBuilder<> ir_builder(next_instruction);
            Value *shm_ptr = call_instruction;
            Value *shm_id = call_instruction->getArgOperand(0);
            std::vector<Value *> check_shmat_args;
            check_shmat_args.push_back(shm_id);
            check_shmat_args.push_back(shm_ptr);
            ir_builder.CreateCall(check_shmat, check_shmat_args);
          }
          if (callee_name == "getenv") {
            auto *next_instruction = call_instruction->getNextNode();
            if (next_instruction != nullptr) {
              errs() << next_instruction << "\n";
            }
            IRBuilder<> ir_builder(next_instruction);
            Value *env_str = call_instruction->getArgOperand(0);
            Value *env_res = call_instruction;
            std::vector<Value *> check_getenv_args;
            check_getenv_args.push_back(env_str);
            check_getenv_args.push_back(env_res);
            ir_builder.CreateCall(check_getenv, check_getenv_args);
          }
          if (callee_name == "tracer_dump") {
            IRBuilder<> ir_builder(call_instruction);
            ir_builder.CreateCall(create_bucket, {});
          }
        }
      }
    }
  }
#endif
}
return true;
}

static RegisterStandardPasses
    optx_definition_checker(PassManagerBuilder::EP_ModuleOptimizerEarly,
                            register_definition_checker);

static RegisterStandardPasses
    opt0_definition_checker(PassManagerBuilder::EP_EnabledOnOptLevel0,
                            register_definition_checker);
