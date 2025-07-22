if [ -z $1 ]
then
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
else
	if [ $1 = "aflnet" ]
	then
		export AFL_SKIP_CPUFREQ=1
		export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
		export AFL_NO_AFFINITY=1
		export AFLNET=/experiments/aflnet/
		export AFL_PATH=/experiments/aflnet/
		export LLVM_CONFIG=llvm-config-10
	elif [ $1 = "stateafl" ]
	then
		export AFL_SKIP_CPUFREQ=1
		export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
		export AFL_NO_AFFINITY=1
		export AFLNET=/experiments/aflnet/
		export AFL_PATH=/experiments/stateafl/
		export LLVM_CONFIG=llvm-config-10
	elif [ $1 = "nsfuzz" ]
	then
		echo "[*]set up nsfuzz ENV"
		export LLVM_DIR=/experiments/llvm-project/build/
		export AFL_CC=/experiments/llvm-project/build/bin/clang
		export AFL_CXX=/experiments/llvm-project/build/bin/clang++
		export CLANG=/experiments/llvm-project/build/bin/clang
		export CLANGXX=/experiments/llvm-project/build/bin/clang++
		export LLVM_CONFIG=/experiments/llvm-project/build/bin/llvm-config-10
		export STATIC=/experiments/nsfuzz/SVAnaluzer
		export NSFUZZ=/experiments/nsfuzz/

		export AFL_SKIP_CPUFREQ=1
		export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
		export AFL_NO_AFFINITY=1
		export AFLNET=/experiments/aflnet/
		export AFL_PATH=/experiments/nsfuzz/
	elif [ $1 = "aflnetlegion" ]
	then
		export AFLNET=/experiments/aflnetlegion/
		export AFL_NET=/experiments/aflnetlegion/
		export AFL_PATH=/experiments/aflnetlegion/
		export AFLNET_LEGION_PATH=/experiments/aflnetlegion/
		export LLVM_CONFIG=llvm-config-10
		export AFL_SKIP_CPUFREQ=1
		export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
		export AFL_NO_AFFINITY=1
	fi
fi

