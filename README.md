
# A Zeek Mach-o File Analysis Package

This package implements:

- Mach-o

## Building and Installing

This plugin can be built with:

```
./configure --zeek-dist=/your/zeek/src/dir
make
sudo make install
```

## Using MACHO

The testing pcap file:  

https://github.com/corelight/zeek-macho/blob/master/tests/Traces/all_executables.pcap

Binaries in this pcap were pulled from:

https://github.com/JonathanSalwan/binary-samples

Once this analyzer is installed, this plugin can be loaded with the following Zeek script:

```
@load Zeek/MACHO

event file_macho_header_raw(f: fa_file, m: Zeek::MACHOHeaderRaw)
    {
    print "====";
    print "MACHO HEADER RAW";
    print m$signature;
    print "====";
    }

event file_macho_single_binary_command(f: fa_file, m: Zeek::MACHOHeaderRaw, cmd_num: count, offset: count, c: Zeek::MACHOCommand)
    {
    print "====";
    print "MACHO SINGLE BINARY COMMAND";
    print offset;
    print cmd_num;
    print c$segname;
    print "====";
    }

event file_macho_universal_binary_arch(f: fa_file, m: Zeek::MACHOHeaderRaw, a: Zeek::MACHOFATArch)
    {
    print "====";
    print "MACHO UNIVERSAL BINARY ARCH";
    print f$id;
    print a;
    print "====";
    }
```

The output should look like this:

```
% zeek -r pcaps/all_binaries.pcap -C macho.zeek
====
MACHO HEADER RAW
\xca\xfe\xba\xbe
====
====
MACHO UNIVERSAL BINARY ARCH
FdLrA12jaXM0aeUFL7
[cpu_type=7, cpu_subtype=3, offset=4096, size=576016, align=12, reserved=<uninitialized>]
====
====
MACHO UNIVERSAL BINARY ARCH
FdLrA12jaXM0aeUFL7
[cpu_type=18, cpu_subtype=10, offset=581632, size=663296, align=12, reserved=<uninitialized>]
====
====
MACHO HEADER RAW
\xcf\xfa\xed\xfe
====
====
MACHO SINGLE BINARY COMMAND
28
1
\x19\x00\x00\x00H\x00\x00\x00__PAGEZE
====
====
MACHO SINGLE BINARY COMMAND
100
2
\x19\x00\x00\x00(\x02\x00\x00__TEXT\x00\x00
====
====
MACHO SINGLE BINARY COMMAND
652
3
\x19\x00\x00\x00\xc8\x02\x00\x00__DATA\x00\x00
====
====
MACHO SINGLE BINARY COMMAND
1364
4
\x19\x00\x00\x00H\x00\x00\x00__LINKED
====
====
MACHO HEADER RAW
\xce\xfa\xed\xfe
====
====
MACHO SINGLE BINARY COMMAND
24
1
\x01\x00\x00\x008\x00\x00\x00__PAGEZE
====
====
MACHO SINGLE BINARY COMMAND
80
2
\x01\x00\x00\x00\x8c\x01\x00\x00__TEXT\x00\x00
====
====
MACHO SINGLE BINARY COMMAND
476
3
\x01\x00\x00\x00\x14\x02\x00\x00__DATA\x00\x00
====
====
MACHO SINGLE BINARY COMMAND
1008
4
\x01\x00\x00\x008\x00\x00\x00__LINKED
====
====
MACHO HEADER RAW
\xce\xfa\xed\xfe
====
====
MACHO HEADER RAW
\xca\xfe\xba\xbe
====
====
MACHO UNIVERSAL BINARY ARCH
FcXhineqH4rVNW5n2
[cpu_type=12, cpu_subtype=9, offset=16384, size=91792, align=14, reserved=<uninitialized>]
====
====
MACHO UNIVERSAL BINARY ARCH
FcXhineqH4rVNW5n2
[cpu_type=12, cpu_subtype=11, offset=114688, size=91792, align=14, reserved=<uninitialized>]
====
====
MACHO UNIVERSAL BINARY ARCH
FcXhineqH4rVNW5n2
[cpu_type=16777228, cpu_subtype=0, offset=212992, size=93248, align=14, reserved=<uninitialized>]
====
====
MACHO HEADER RAW
\xce\xfa\xed\xfe
====
====
MACHO HEADER RAW
\xcf\xfa\xed\xfe
====
====
MACHO SINGLE BINARY COMMAND
28
1
\x19\x00\x00\x00H\x00\x00\x00__PAGEZE
====
====
MACHO SINGLE BINARY COMMAND
100
2
\x19\x00\x00\x00(\x02\x00\x00__TEXT\x00\x00
====
====
MACHO SINGLE BINARY COMMAND
652
3
\x19\x00\x00\x00\xe8\x00\x00\x00__DATA_C
====
====
MACHO SINGLE BINARY COMMAND
884
4
\x19\x00\x00\x00\x88\x01\x00\x00__DATA\x00\x00
====
====
MACHO SINGLE BINARY COMMAND
1276
5
\x19\x00\x00\x00H\x00\x00\x00__LINKED
====
====
MACHO HEADER RAW
\xca\xfe\xba\xbe
====
====
MACHO UNIVERSAL BINARY ARCH
FYXjlFG0LU4PmVdYg
[cpu_type=16777223, cpu_subtype=3, offset=4096, size=26864, align=12, reserved=<uninitialized>]
====
====
MACHO UNIVERSAL BINARY ARCH
FYXjlFG0LU4PmVdYg
[cpu_type=7, cpu_subtype=3, offset=32768, size=26320, align=12, reserved=<uninitialized>]
====

% cat files.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files
#open	2019-12-16-10-29-55
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	duration	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff	extracted_size
#types	time	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	interval	bool	bool	count	count	count	count	bool	string	string	string	string	string	bool	count
1575573054.714905	FdLrA12jaXM0aeUFL7	127.0.0.1	127.0.0.1	CxtoJD1vAp3SAL6Sxa	HTTP	0	MACHO	application/x-mach-o-executable	-	0.017705	-	F	1244928	1244928	0	0	F	-	-	-	-	-	-	-
1575573054.748160	Fa366V2TpUNaGJHQT9	127.0.0.1	127.0.0.1	CylX6c1KHZ0EwM06U3	HTTP	0	(empty)	-	-	0.007859	-	F	450568	450568	0	0	F	-	-	-	-	-	-	-
1575573054.771418	FzLp3E23ljWzpUhjYb	127.0.0.1	127.0.0.1	CcJKvMezJ9TNOhHL4	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000020	-	F	39584	39584	0	0	F	-	-	-	-	-	-	-
1575573054.786828	FT0BPEFTGWsUJnKq5	127.0.0.1	127.0.0.1	CjmFig4ABur1iYqH4d	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000028	-	F	35696	35696	0	0	F	-	-	-	-	-	-	-
1575573054.805742	FpsfRh42ET7tOfLZSa	127.0.0.1	127.0.0.1	CmKoMf1ltIDMiZPima	HTTP	0	MACHO	application/x-mach-o-executable	-	0.009188	-	F	546768	546768	0	0	F	-	-	-	-	-	-	-
1575573054.831830	FcXhineqH4rVNW5n2	127.0.0.1	127.0.0.1	CMWdMs1R2GehAArRv5	HTTP	0	MACHO	application/x-mach-o-executable	-	0.006384	-	F	306240	306240	0	0	F	-	-	-	-	-	-	-
1575573054.856230	Fi71fa4AoXLFkyBZxc	127.0.0.1	127.0.0.1	C5CyRL3CKWQ7mx8yk9	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000851	-	F	91792	91792	0	0	F	-	-	-	-	-	-	-
1575573054.870413	Ff9tRIJzK5SSo0Mfe	127.0.0.1	127.0.0.1	CYGjah44KvN4fUoql1	HTTP	0	(empty)	application/x-executable	-	0.000027	-	F	8088	8088	0	0	F	-	-	-	-	-	-	-
1575573054.884851	FOYYch36HZTvrQPlTi	127.0.0.1	127.0.0.1	C7b9id4JIofsroEika	HTTP	0	(empty)	application/x-executable	-	0.044493	-	F	2573932	2573932	0	0	F	-	-	-	-	-	-	-
1575573054.945714	FPx37D1lITkX5Ihrx5	127.0.0.1	127.0.0.1	CK7zsr1GdzIXU3lqKl	HTTP	0	(empty)	application/x-sharedlib	-	0.001765	-	F	173604	173604	0	0	F	-	-	-	-	-	-	-
1575573054.960002	FfTba01VvghPWqT3Gc	127.0.0.1	127.0.0.1	C2L8yiffwefJGdZij	HTTP	0	(empty)	application/x-sharedlib	-	0.009696	-	F	733535	733535	0	0	F	-	-	-	-	-	-	-
1575573054.985255	Fhtxt04pKjMXuz3xkg	127.0.0.1	127.0.0.1	ClIS25MBjMfsTqkD1	HTTP	0	(empty)	application/x-executable	-	0.014386	-	F	847400	847400	0	0	F	-	-	-	-	-	-	-
1575573055.014785	FiQK8tHSTDLqHj481	127.0.0.1	127.0.0.1	CLdCvP2S3XkpjeDqS	HTTP	0	(empty)	application/x-executable	-	0.000978	-	F	90808	90808	0	0	F	-	-	-	-	-	-	-
1575573055.029562	F7ydFjDejfkK5p93g	127.0.0.1	127.0.0.1	CghFyD2L9NUmUQYBBl	HTTP	0	(empty)	application/x-executable	-	0.014827	-	F	926576	926576	0	0	F	-	-	-	-	-	-	-
1575573055.059888	F61rl1HjvAvod4IKf	127.0.0.1	127.0.0.1	CYkhfL1vSZlBAcJTQc	HTTP	0	(empty)	application/x-executable	-	0.013047	-	F	903556	903556	0	0	F	-	-	-	-	-	-	-
1575573055.086529	FrniXj4G5FBbipKAXj	127.0.0.1	127.0.0.1	C2oGU9rkWOcBmCOk2	HTTP	0	(empty)	application/x-executable	-	0.010830	-	F	954028	954028	0	0	F	-	-	-	-	-	-	-
1575573055.111601	Foa6OD353qEAod1Rtd	127.0.0.1	127.0.0.1	CNoQ0f92BZesFkog3	HTTP	0	(empty)	application/x-executable	-	0.010550	-	F	856496	856496	0	0	F	-	-	-	-	-	-	-
1575573055.136312	FlQg1C3yoYu4Ii79G1	127.0.0.1	127.0.0.1	CeFLUd3ymDkRpBOnKi	HTTP	0	(empty)	application/x-executable	-	0.008135	-	F	693024	693024	0	0	F	-	-	-	-	-	-	-
1575573055.158362	FDpoEk1h413vhqsAY7	127.0.0.1	127.0.0.1	CUMhkgHpG8wY9xX3	HTTP	0	(empty)	application/x-executable	-	0.008786	-	F	770392	770392	0	0	F	-	-	-	-	-	-	-
1575573055.180801	FfJxYq2UH8pobDAyh	127.0.0.1	127.0.0.1	ClSJ7p29IEYBGO0qol	HTTP	0	(empty)	application/x-executable	-	0.020865	-	F	1486344	1486344	0	0	F	-	-	-	-	-	-	-
1575573055.219834	FJCWvz4H8NXellwgQg	127.0.0.1	127.0.0.1	CJ02x93rtdCeQRwi3d	HTTP	0	(empty)	application/x-sharedlib	-	0.022064	-	F	1145944	1145944	0	0	F	-	-	-	-	-	-	-
1575573055.258825	FD0tNZ191kLavvTgy8	127.0.0.1	127.0.0.1	CHFN3VxPRyhV2OsM6	HTTP	0	(empty)	application/x-sharedlib	-	0.023405	-	F	1134116	1134116	0	0	F	-	-	-	-	-	-	-
1575573055.297420	F5xbP13O6XYTMLgcma	127.0.0.1	127.0.0.1	C7Ucim1qeEfGr4vDJh	HTTP	0	(empty)	application/x-executable	-	0.016132	-	F	851464	851464	0	0	F	-	-	-	-	-	-	-
1575573055.329918	FxsJOG1mVPjddyfuSe	127.0.0.1	127.0.0.1	CoZ4ij2Zq06hoZKxm3	HTTP	0	(empty)	application/x-executable	-	0.016251	-	F	926536	926536	0	0	F	-	-	-	-	-	-	-
1575573055.369187	FsZcQB8W5LMIbZCA1	127.0.0.1	127.0.0.1	CMCowK3t3rYp4bE2y2	HTTP	0	(empty)	application/x-executable	-	0.011578	-	F	811156	811156	0	0	F	-	-	-	-	-	-	-
1575573055.398939	FZhVgl2N790Dfa2FFa	127.0.0.1	127.0.0.1	Cm2ITy2nZd7OUpCVJc	HTTP	0	(empty)	application/x-sharedlib	-	0.000000	-	F	9552	9552	0	0	F	-	-	-	-	-	-	-
1575573055.415558	FoAJTP3Sasv7vDJRW7	127.0.0.1	127.0.0.1	Ct9EiTTil8dMsHu2d	HTTP	0	(empty)	application/x-sharedlib	-	0.008120	-	F	563936	563936	0	0	F	-	-	-	-	-	-	-
1575573055.441153	FlRQhc4ipvfl75f289	127.0.0.1	127.0.0.1	CwXCaW0lsfc0KQWog	HTTP	0	(empty)	application/x-executable	-	0.007160	-	F	401436	401436	0	0	F	-	-	-	-	-	-	-
1575573055.463867	FkwXG93nBmzNl2DOyj	127.0.0.1	127.0.0.1	CGjxVT25tI84tJMxD2	HTTP	0	(empty)	application/x-executable	-	0.007288	-	F	436765	436765	0	0	F	-	-	-	-	-	-	-
1575573055.498662	Fn2NC31bzy2NH8Wt04	127.0.0.1	127.0.0.1	COU3VZ2xEBbcwE0Rqc	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000022	-	F	65040	65040	0	0	F	-	-	-	-	-	-	-
1575573055.515049	FYXjlFG0LU4PmVdYg	127.0.0.1	127.0.0.1	C3YVG53MQpUuJcj3zh	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000056	-	F	59088	59088	0	0	F	-	-	-	-	-	-	-
1575573055.533650	F3tpQ24gwPmAINB1ri	127.0.0.1	127.0.0.1	CKkHPrI1mhc45G1Dg	HTTP	0	PE	application/x-dosexec	-	0.000000	-	F	6656	6656	0	0	F	-	-	-	-	-	-	-
1575573055.549630	FId7Y313XTAGt3u333	127.0.0.1	127.0.0.1	CfDajp1HnHz9Rn2YG8	HTTP	0	PE	application/x-dosexec	-	0.006863	-	F	345088	345088	0	0	F	-	-	-	-	-	-	-
1575573055.572433	Fg4xin2mdkzOE1JrJk	127.0.0.1	127.0.0.1	CXXe9k4pjeUbSw5K3d	HTTP	0	PE	application/x-dosexec	-	0.004190	-	F	301568	301568	0	0	F	-	-	-	-	-	-	-
1575573055.593431	FAoNZT3AgAf5H3hzg2	127.0.0.1	127.0.0.1	CHbOJb1LjssvtbX0u3	HTTP	0	PE	application/x-dosexec	-	0.001843	-	F	135197	135197	0	0	F	-	-	-	-	-	-	-
1575573055.610819	FPxiZq2WmMpcqRuJhe	127.0.0.1	127.0.0.1	CCMZ6D2a85vPJAvtF2	HTTP	0	PE	application/x-dosexec	-	0.016037	-	F	1160718	1160718	0	0	F	-	-	-	-	-	-	-
#close	2019-12-16-10-29-55

% cat macho.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	macho
#open	2019-12-16-10-29-55
#fields	ts	id	signature	is_64bit	little_endian	is_universal_binary	num_binaries	cpu_types	cpu_subtypes	image_offsets	image_sizes	filetype	ncmds	sizeofcmds	flags
#types	time	string	string	bool	bool	bool	count	vector[string]	vector[string]	vector[count]	vector[count]	string	count	count	string
1575573054.714905	FdLrA12jaXM0aeUFL7	0xCAFEBABE	F	F	T	2	x86,POWERPC	386,7400	4096,581632	576016,663296	-	-	-	-
1575573054.771418	FzLp3E23ljWzpUhjYb	0xFEEDFACF	T	T	F	-	x86_64	ALL	(empty)	(empty)	MH_EXECUTE	16	2008	0x00200085
1575573054.786828	FT0BPEFTGWsUJnKq5	0xFEEDFACE	F	T	F	-	x86	386	(empty)	(empty)	MH_EXECUTE	16	1528	0x01200085
1575573054.805742	FpsfRh42ET7tOfLZSa	0xFEEDFACE	F	T	F	-	ARM	ALL	(empty)	(empty)	MH_EXECUTE	15	1560	0x00000085
1575573054.831830	FcXhineqH4rVNW5n2	0xCAFEBABE	F	F	T	3	ARM,ARM,ARM64	V7,V7S,ALL	16384,114688,212992	91792,91792,93248	-	-	-	-
1575573054.856230	Fi71fa4AoXLFkyBZxc	0xFEEDFACE	F	T	F	-	ARM	V7S	(empty)	(empty)	MH_EXECUTE	24	2452	0x00200085
1575573055.498662	Fn2NC31bzy2NH8Wt04	0xFEEDFACF	T	T	F	-	x86_64	ALL	(empty)	(empty)	MH_EXECUTE	17	1704	0x00200085
1575573055.515049	FYXjlFG0LU4PmVdYg	0xCAFEBABE	F	F	T	2	x86_64,x86	ALL,386	4096,32768	26864,26320	-	-	-	-
#close	2019-12-16-10-29-55
```

Enjoy!

## License:

This application(s) is/are covered by the Creative Commons BY-SA license.