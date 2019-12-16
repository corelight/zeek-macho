
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

https://github.com/corelight/zeek-elf/blob/master/tests/Traces/all_executables.pcap

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
    print m;
    print c;
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
MACHO HEADER RAW
\xce\xfa\xed\xfe
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
#open	2019-12-16-07-16-44
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	duration	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff	extracted_size
#types	time	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	interval	bool	bool	count	count	count	count	bool	string	string	string	string	string	bool	count
1575573054.714905	FdLrA12jaXM0aeUFL7	127.0.0.1	127.0.0.1	COTEOm1Jo0V14zCisj	HTTP	0	MACHO	application/x-mach-o-executable	-	0.017705	-	F	1244928	1244928	0	0	F	-	-	-	-	-	-	-
1575573054.748160	Fa366V2TpUNaGJHQT9	127.0.0.1	127.0.0.1	ChmOXh2y2M9VTFBnc8	HTTP	0	(empty)	-	-	0.007859	-	F	450568	450568	0	0	F	-	-	-	-	-	-	-
1575573054.771418	FzLp3E23ljWzpUhjYb	127.0.0.1	127.0.0.1	Cm02Sq1SG31vGiezhd	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000020	-	F	39584	39584	0	0	F	-	-	-	-	-	-	-
1575573054.786828	FT0BPEFTGWsUJnKq5	127.0.0.1	127.0.0.1	CwEK1F2BOuhNUJF1R9	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000028	-	F	35696	35696	0	0	F	-	-	-	-	-	-	-
1575573054.805742	FpsfRh42ET7tOfLZSa	127.0.0.1	127.0.0.1	CrvMhh2uO5FG6zgRdi	HTTP	0	MACHO	application/x-mach-o-executable	-	0.009188	-	F	546768	546768	0	0	F	-	-	-	-	-	-	-
1575573054.831830	FcXhineqH4rVNW5n2	127.0.0.1	127.0.0.1	CdGMu12cJusiox6PP7	HTTP	0	MACHO	application/x-mach-o-executable	-	0.006384	-	F	306240	306240	0	0	F	-	-	-	-	-	-	-
1575573054.856230	Fi71fa4AoXLFkyBZxc	127.0.0.1	127.0.0.1	CsUDsc4hQO7BW2A1Ph	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000851	-	F	91792	91792	0	0	F	-	-	-	-	-	-	-
1575573054.870413	Ff9tRIJzK5SSo0Mfe	127.0.0.1	127.0.0.1	CXruoO2azWBkh0Nj5k	HTTP	0	(empty)	application/x-executable	-	0.000027	-	F	8088	8088	0	0	F	-	-	-	-	-	-	-
1575573054.884851	FOYYch36HZTvrQPlTi	127.0.0.1	127.0.0.1	CXoc7B1iXuCIiAdhgb	HTTP	0	(empty)	application/x-executable	-	0.044493	-	F	2573932	2573932	0	0	F	-	-	-	-	-	-	-
1575573054.945714	FPx37D1lITkX5Ihrx5	127.0.0.1	127.0.0.1	Cgawwl1oTmlObDKW66	HTTP	0	(empty)	application/x-sharedlib	-	0.001765	-	F	173604	173604	0	0	F	-	-	-	-	-	-	-
1575573054.960002	FfTba01VvghPWqT3Gc	127.0.0.1	127.0.0.1	CT9CtE4T0auUZWlK8a	HTTP	0	(empty)	application/x-sharedlib	-	0.009696	-	F	733535	733535	0	0	F	-	-	-	-	-	-	-
1575573054.985255	Fhtxt04pKjMXuz3xkg	127.0.0.1	127.0.0.1	C7aK8JscKeqMcTBSf	HTTP	0	(empty)	application/x-executable	-	0.014386	-	F	847400	847400	0	0	F	-	-	-	-	-	-	-
1575573055.014785	FiQK8tHSTDLqHj481	127.0.0.1	127.0.0.1	CRuMso2ZAtc4rKCdH6	HTTP	0	(empty)	application/x-executable	-	0.000978	-	F	90808	90808	0	0	F	-	-	-	-	-	-	-
1575573055.029562	F7ydFjDejfkK5p93g	127.0.0.1	127.0.0.1	CUKyyYJrVZIedWl8f	HTTP	0	(empty)	application/x-executable	-	0.014827	-	F	926576	926576	0	0	F	-	-	-	-	-	-	-
1575573055.059888	F61rl1HjvAvod4IKf	127.0.0.1	127.0.0.1	CorsTvhSgcFpOJgv6	HTTP	0	(empty)	application/x-executable	-	0.013047	-	F	903556	903556	0	0	F	-	-	-	-	-	-	-
1575573055.086529	FrniXj4G5FBbipKAXj	127.0.0.1	127.0.0.1	CNN1NR3r12ktWoVZG3	HTTP	0	(empty)	application/x-executable	-	0.010830	-	F	954028	954028	0	0	F	-	-	-	-	-	-	-
1575573055.111601	Foa6OD353qEAod1Rtd	127.0.0.1	127.0.0.1	C1jkgi22wVDUj4Phig	HTTP	0	(empty)	application/x-executable	-	0.010550	-	F	856496	856496	0	0	F	-	-	-	-	-	-	-
1575573055.136312	FlQg1C3yoYu4Ii79G1	127.0.0.1	127.0.0.1	CYpsku2ETaygL8b0Of	HTTP	0	(empty)	application/x-executable	-	0.008135	-	F	693024	693024	0	0	F	-	-	-	-	-	-	-
1575573055.158362	FDpoEk1h413vhqsAY7	127.0.0.1	127.0.0.1	CHFAUK1z1YW8ScfcI7	HTTP	0	(empty)	application/x-executable	-	0.008786	-	F	770392	770392	0	0	F	-	-	-	-	-	-	-
1575573055.180801	FfJxYq2UH8pobDAyh	127.0.0.1	127.0.0.1	C9qPcWsL588Nk6OJ5	HTTP	0	(empty)	application/x-executable	-	0.020865	-	F	1486344	1486344	0	0	F	-	-	-	-	-	-	-
1575573055.219834	FJCWvz4H8NXellwgQg	127.0.0.1	127.0.0.1	C6xKpa3E6OsYgaDKs7	HTTP	0	(empty)	application/x-sharedlib	-	0.022064	-	F	1145944	1145944	0	0	F	-	-	-	-	-	-	-
1575573055.258825	FD0tNZ191kLavvTgy8	127.0.0.1	127.0.0.1	CE6wsXSePqJt0DkJj	HTTP	0	(empty)	application/x-sharedlib	-	0.023405	-	F	1134116	1134116	0	0	F	-	-	-	-	-	-	-
1575573055.297420	F5xbP13O6XYTMLgcma	127.0.0.1	127.0.0.1	CoTBKP3e01TNGyoz7k	HTTP	0	(empty)	application/x-executable	-	0.016132	-	F	851464	851464	0	0	F	-	-	-	-	-	-	-
1575573055.329918	FxsJOG1mVPjddyfuSe	127.0.0.1	127.0.0.1	CeFLxwIJ7E6rHm7V9	HTTP	0	(empty)	application/x-executable	-	0.016251	-	F	926536	926536	0	0	F	-	-	-	-	-	-	-
1575573055.369187	FsZcQB8W5LMIbZCA1	127.0.0.1	127.0.0.1	C8vUOR7aWJJNobKUi	HTTP	0	(empty)	application/x-executable	-	0.011578	-	F	811156	811156	0	0	F	-	-	-	-	-	-	-
1575573055.398939	FZhVgl2N790Dfa2FFa	127.0.0.1	127.0.0.1	CkfMjmFoD2ItZERw1	HTTP	0	(empty)	application/x-sharedlib	-	0.000000	-	F	9552	9552	0	0	F	-	-	-	-	-	-	-
1575573055.415558	FoAJTP3Sasv7vDJRW7	127.0.0.1	127.0.0.1	CxODJs1FNxoj9cKmU6	HTTP	0	(empty)	application/x-sharedlib	-	0.008120	-	F	563936	563936	0	0	F	-	-	-	-	-	-	-
1575573055.441153	FlRQhc4ipvfl75f289	127.0.0.1	127.0.0.1	CGPQgm13WmKCcLveci	HTTP	0	(empty)	application/x-executable	-	0.007160	-	F	401436	401436	0	0	F	-	-	-	-	-	-	-
1575573055.463867	FkwXG93nBmzNl2DOyj	127.0.0.1	127.0.0.1	C10VQx3iHho6He47A7	HTTP	0	(empty)	application/x-executable	-	0.007288	-	F	436765	436765	0	0	F	-	-	-	-	-	-	-
1575573055.498662	Fn2NC31bzy2NH8Wt04	127.0.0.1	127.0.0.1	CGqOnr33Lf3myabHdj	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000022	-	F	65040	65040	0	0	F	-	-	-	-	-	-	-
1575573055.515049	FYXjlFG0LU4PmVdYg	127.0.0.1	127.0.0.1	CRGpLr2FjkHlRXcOh1	HTTP	0	MACHO	application/x-mach-o-executable	-	0.000056	-	F	59088	59088	0	0	F	-	-	-	-	-	-	-
1575573055.533650	F3tpQ24gwPmAINB1ri	127.0.0.1	127.0.0.1	CJuHS42ecSOl7i4oG4	HTTP	0	PE	application/x-dosexec	-	0.000000	-	F	6656	6656	0	0	F	-	-	-	-	-	-	-
1575573055.549630	FId7Y313XTAGt3u333	127.0.0.1	127.0.0.1	CL4pJi4EJNHyCP0Q6f	HTTP	0	PE	application/x-dosexec	-	0.006863	-	F	345088	345088	0	0	F	-	-	-	-	-	-	-
1575573055.572433	Fg4xin2mdkzOE1JrJk	127.0.0.1	127.0.0.1	Cj11WI0Q8Oya8th65	HTTP	0	PE	application/x-dosexec	-	0.004190	-	F	301568	301568	0	0	F	-	-	-	-	-	-	-
1575573055.593431	FAoNZT3AgAf5H3hzg2	127.0.0.1	127.0.0.1	CY9FZk1FGiamAXnEf2	HTTP	0	PE	application/x-dosexec	-	0.001843	-	F	135197	135197	0	0	F	-	-	-	-	-	-	-
1575573055.610819	FPxiZq2WmMpcqRuJhe	127.0.0.1	127.0.0.1	CTeeFj2gVrCwN6z8ab	HTTP	0	PE	application/x-dosexec	-	0.016037	-	F	1160718	1160718	0	0	F	-	-	-	-	-	-	-
#close	2019-12-16-07-16-44

% cat macho.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	macho
#open	2019-12-16-07-16-44
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
#close	2019-12-16-07-16-44
```

Enjoy!

## License:

This application(s) is/are covered by the Creative Commons BY-SA license.