if [ -z $1 ]; then
  echo "[*]clear all the fuzzer env"
  unset AFLNET
  unset AFL_PATH
  unset AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES
  unset AFL_SKIP_CPUFREQ
  unset LLVM_CONFIG
  unset NSFUZZ
  unset STATIC
  unset CLANG
  unset CLANGXX
  unset AFL_CC
  unset AFL_CXX
  unset DEFINITION_CHECKER_LIST
else
  if [ $1 = "aflnet" ]; then
    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFLNET=$HOME/experiments/fuzzers/aflnet/
    export AFL_PATH=$HOME/experiments/fuzzers/aflnet/
    export LLVM_CONFIG=llvm-config-10
  elif [ $1 = "stateafl" ]; then
    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFLNET=$HOME/experiments/fuzzers/aflnet/
    export AFL_PATH=$HOME/experiments/fuzzers/stateafl/
    export LLVM_CONFIG=llvm-config-10
  elif [ $1 = "nsfuzz" ]; then
    echo "[*]set up nsfuzz ENV"
    export LLVM_DIR=$HOME/experiments/llvm-project/build/
    export AFL_CC=clang
    export AFL_CXX=clang++
    export CLANG=clang
    export CLANGXX=clang++
    export LLVM_CONFIG=llvm-config-10
    export STATIC=$HOME/experiments/fuzzers/nsfuzz/PreAnalysis/SVAnalyzer
    export NSFUZZ=$HOME/experiments/fuzzers/nsfuzz/

    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFLNET=$HOME/experiments/fuzzers/aflnet/
    export AFL_PATH=$HOME/experiments/fuzzers/nsfuzz/
  elif [ $1 = "aflnetlegion" ]; then
    export AFLNET=$HOME/experiments/fuzzers/aflnetlegion/
    export AFL_NET=$HOME/experiments/fuzzers/aflnetlegion/
    export AFL_PATH=$HOME/experiments/fuzzers/aflnetlegion/
    export AFLNET_LEGION_PATH=$HOME/experiments/fuzzers/aflnetlegion/
    export LLVM_CONFIG=llvm-config-10
    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_NO_AFFINITY=1
  fi
  export DEFINITION_CHECKER_LIST=$HOME
fi
