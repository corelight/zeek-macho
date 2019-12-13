#
# Definitions from:
# https://github.com/llvm/llvm-project/blob/master/llvm/include/llvm/BinaryFormat/MachO.h
#
module MACHO;

export {
	const cpu_types: table[count] of string = {
		[07]  				= "x86",
		[07 | 0x01000000]  	= "x86_64",
		[10] 				= "MC98000",
		[12] 				= "ARM",
		[12 | 0x01000000] 	= "ARM64",
		[12 | 0x02000000] 	= "ARM64_32",
		[14] 				= "SPARC",
		[18] 				= "POWERPC",
		[18 | 0x01000000] 	= "POWERPC64"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const filetypes: table[count] of string = {
		[1]  				= "MH_OBJECT",
		[2]  				= "MH_EXECUTE",
		[3]  				= "MH_FVMLIB",
		[4]  				= "MH_CORE",
		[5]  				= "MH_PRELOAD",
		[6]  				= "MH_DYLIB",
		[7]  				= "MH_DYLINKER",
		[8]  				= "MH_BUNDLE",
		[9]  				= "MH_DYLIB_STUB",
		[10]  				= "MH_DSYM",
		[11]  				= "MH_KEXT_BUNDLE"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const x86subtypes: table[count] of string = {
		[3]  				= "386",
		[4]  				= "486",
		[0x84] 				= "486SX",
		[5]  				= "586"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const x86_64subtypes: table[count] of string = {
		[3]  				= "ALL",
		[4]  				= "ARCH1",
		[8] 				= "64_H"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const ARMsubtypes: table[count] of string = {
		[0]  				= "ALL",
		[5]  				= "V4T",
		[6]  				= "V6",
		[7] 				= "V5",
		[8] 				= "XSCALE",
		[9] 				= "V7",
		[11] 				= "V7S",
		[12] 				= "V7K",
		[14] 				= "V6M",
		[15] 				= "V7M",
		[16] 				= "V7EM"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const ARM64subtypes: table[count] of string = {
		[0]  				= "ALL",
		[2] 				= "64E"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const ARM64_32subtypes: table[count] of string = {
		[1]  				= "V8"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const PowerPCsubtypes: table[count] of string = {
		[0]  				= "ALL",
		[1]  				= "601",
		[2]  				= "602",
		[3]  				= "603",
		[4]  				= "603e",
		[5]  				= "603ev",
		[6]  				= "604",
		[7]  				= "604e",
		[8]  				= "620",
		[9]  				= "750",
		[10]  				= "7400",
		[11]  				= "7450",
		[100]  				= "970"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

}
