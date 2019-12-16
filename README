
# A Zeek ELF Package

This package implements:

- ELF

## Building and Installing

This plugin can be built with:

```
./configure --zeek-dist=/your/zeek/src/dir
make
sudo make install
```

## Using ELF

The testing pcap file:  

https://github.com/corelight/zeek-macho/blob/master/tests/Traces/all_executables.pcap

Binaries in this pcap were pulled from:

https://github.com/JonathanSalwan/binary-samples

Once installed, this plugin can be loaded with the following Zeek script:

```
@load Zeek/ELF

event file_elf(f: fa_file)
    {
    print "ELF";
    }

event file_elf_header(f: fa_file, m: Zeek::ELFHeader)
    {
    print "====";
    print "ELF HEADER";
    print m$signature;
    print "====";
    }
```

The output should look like this:

```
% zeek -r pcaps/all_binaries.pcap -C elf.zeek
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====
ELF
====
ELF HEADER
2135247942
====

% cat files.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files
#open	2019-12-16-07-20-46
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	duration	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff	extracted_size
#types	time	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	interval	bool	bool	count	count	count	count	bool	string	string	string	string	string	bool	count
1575573054.714905	FdLrA12jaXM0aeUFL7	127.0.0.1	127.0.0.1	CUsnXfgMISJXzMWl	HTTP	0	(empty)	application/x-mach-o-executable	-	0.017705	-	F	1244928	1244928	0	0	F	-	-	-	-	-	-	-
1575573054.748160	Fa366V2TpUNaGJHQT9	127.0.0.1	127.0.0.1	CS9fG617z9jCRSoOa	HTTP	0	(empty)	-	-	0.007859	-	F	450568	450568	0	0	F	-	-	-	-	-	-	-
1575573054.771418	FzLp3E23ljWzpUhjYb	127.0.0.1	127.0.0.1	CgsJUT1hpQDBQ71hce	HTTP	0	(empty)	application/x-mach-o-executable	-	0.000020	-	F	39584	39584	0	0	F	-	-	-	-	-	-	-
1575573054.786828	FT0BPEFTGWsUJnKq5	127.0.0.1	127.0.0.1	CtQaG6N1dWo4oco5l	HTTP	0	(empty)	application/x-mach-o-executable	-	0.000028	-	F	35696	35696	0	0	F	-	-	-	-	-	-	-
1575573054.805742	FpsfRh42ET7tOfLZSa	127.0.0.1	127.0.0.1	CIIN5h2KGUEuaPjqKh	HTTP	0	(empty)	application/x-mach-o-executable	-	0.009188	-	F	546768	546768	0	0	F	-	-	-	-	-	-	-
1575573054.831830	FcXhineqH4rVNW5n2	127.0.0.1	127.0.0.1	CYyHuB1glRgcS2Vyii	HTTP	0	(empty)	application/x-mach-o-executable	-	0.006384	-	F	306240	306240	0	0	F	-	-	-	-	-	-	-
1575573054.856230	Fi71fa4AoXLFkyBZxc	127.0.0.1	127.0.0.1	C2kqNv4DawOqMe5ry7	HTTP	0	(empty)	application/x-mach-o-executable	-	0.000851	-	F	91792	91792	0	0	F	-	-	-	-	-	-	-
1575573054.870413	Ff9tRIJzK5SSo0Mfe	127.0.0.1	127.0.0.1	CdaEiw2xzOZ9jz9im6	HTTP	0	ELF	application/x-executable	-	0.000027	-	F	8088	8088	0	0	F	-	-	-	-	-	-	-
1575573054.884851	FOYYch36HZTvrQPlTi	127.0.0.1	127.0.0.1	CBG3i71M9nuzfaXEud	HTTP	0	ELF	application/x-executable	-	0.044493	-	F	2573932	2573932	0	0	F	-	-	-	-	-	-	-
1575573054.945714	FPx37D1lITkX5Ihrx5	127.0.0.1	127.0.0.1	CJw0Ss484lbqNybRZj	HTTP	0	ELF	application/x-sharedlib	-	0.001765	-	F	173604	173604	0	0	F	-	-	-	-	-	-	-
1575573054.960002	FfTba01VvghPWqT3Gc	127.0.0.1	127.0.0.1	CbnrdUUZAstBGBZ75	HTTP	0	ELF	application/x-sharedlib	-	0.009696	-	F	733535	733535	0	0	F	-	-	-	-	-	-	-
1575573054.985255	Fhtxt04pKjMXuz3xkg	127.0.0.1	127.0.0.1	Cl06PP3XRxzU69Iys	HTTP	0	ELF	application/x-executable	-	0.014386	-	F	847400	847400	0	0	F	-	-	-	-	-	-	-
1575573055.014785	FiQK8tHSTDLqHj481	127.0.0.1	127.0.0.1	CyuRHq48i5kVXQgkM5	HTTP	0	ELF	application/x-executable	-	0.000978	-	F	90808	90808	0	0	F	-	-	-	-	-	-	-
1575573055.029562	F7ydFjDejfkK5p93g	127.0.0.1	127.0.0.1	C9fqvh4g4sClJn6eO3	HTTP	0	ELF	application/x-executable	-	0.014827	-	F	926576	926576	0	0	F	-	-	-	-	-	-	-
1575573055.059888	F61rl1HjvAvod4IKf	127.0.0.1	127.0.0.1	CAy2eY125hUwNXCGbk	HTTP	0	ELF	application/x-executable	-	0.013047	-	F	903556	903556	0	0	F	-	-	-	-	-	-	-
1575573055.086529	FrniXj4G5FBbipKAXj	127.0.0.1	127.0.0.1	CJMXEO2VRQru2SRNz9	HTTP	0	ELF	application/x-executable	-	0.010830	-	F	954028	954028	0	0	F	-	-	-	-	-	-	-
1575573055.111601	Foa6OD353qEAod1Rtd	127.0.0.1	127.0.0.1	CVFUXh3NqiYfqJIWQ4	HTTP	0	ELF	application/x-executable	-	0.010550	-	F	856496	856496	0	0	F	-	-	-	-	-	-	-
1575573055.136312	FlQg1C3yoYu4Ii79G1	127.0.0.1	127.0.0.1	CpoRiHdpdmMXkuHS1	HTTP	0	ELF	application/x-executable	-	0.008135	-	F	693024	693024	0	0	F	-	-	-	-	-	-	-
1575573055.158362	FDpoEk1h413vhqsAY7	127.0.0.1	127.0.0.1	CxwXaloXHaOhI8Wm2	HTTP	0	ELF	application/x-executable	-	0.008786	-	F	770392	770392	0	0	F	-	-	-	-	-	-	-
1575573055.180801	FfJxYq2UH8pobDAyh	127.0.0.1	127.0.0.1	C2LKdf1glmSxCFOuGd	HTTP	0	ELF	application/x-executable	-	0.020865	-	F	1486344	1486344	0	0	F	-	-	-	-	-	-	-
1575573055.219834	FJCWvz4H8NXellwgQg	127.0.0.1	127.0.0.1	CYXOVc3aVTTCl70Zme	HTTP	0	ELF	application/x-sharedlib	-	0.022064	-	F	1145944	1145944	0	0	F	-	-	-	-	-	-	-
1575573055.258825	FD0tNZ191kLavvTgy8	127.0.0.1	127.0.0.1	CQVFIu16YQEEnXWWhk	HTTP	0	ELF	application/x-sharedlib	-	0.023405	-	F	1134116	1134116	0	0	F	-	-	-	-	-	-	-
1575573055.297420	F5xbP13O6XYTMLgcma	127.0.0.1	127.0.0.1	COKIeH1ZDhHnxxnuMf	HTTP	0	ELF	application/x-executable	-	0.016132	-	F	851464	851464	0	0	F	-	-	-	-	-	-	-
1575573055.329918	FxsJOG1mVPjddyfuSe	127.0.0.1	127.0.0.1	CcnT6D1Cvv4lodSpDg	HTTP	0	ELF	application/x-executable	-	0.016251	-	F	926536	926536	0	0	F	-	-	-	-	-	-	-
1575573055.369187	FsZcQB8W5LMIbZCA1	127.0.0.1	127.0.0.1	CVd3rC4EpjgRDXw784	HTTP	0	ELF	application/x-executable	-	0.011578	-	F	811156	811156	0	0	F	-	-	-	-	-	-	-
1575573055.398939	FZhVgl2N790Dfa2FFa	127.0.0.1	127.0.0.1	CU7se13E5F8KRFCXxe	HTTP	0	ELF	application/x-sharedlib	-	0.000000	-	F	9552	9552	0	0	F	-	-	-	-	-	-	-
1575573055.415558	FoAJTP3Sasv7vDJRW7	127.0.0.1	127.0.0.1	CcHkpq4N6GSANva1Q3	HTTP	0	ELF	application/x-sharedlib	-	0.008120	-	F	563936	563936	0	0	F	-	-	-	-	-	-	-
1575573055.441153	FlRQhc4ipvfl75f289	127.0.0.1	127.0.0.1	CYocHp3HaTFiaaHhZ8	HTTP	0	ELF	application/x-executable	-	0.007160	-	F	401436	401436	0	0	F	-	-	-	-	-	-	-
1575573055.463867	FkwXG93nBmzNl2DOyj	127.0.0.1	127.0.0.1	CPjzlg3IrtjBkS6V57	HTTP	0	ELF	application/x-executable	-	0.007288	-	F	436765	436765	0	0	F	-	-	-	-	-	-	-
1575573055.498662	Fn2NC31bzy2NH8Wt04	127.0.0.1	127.0.0.1	CNFzvO12Ao77lYeeR7	HTTP	0	(empty)	application/x-mach-o-executable	-	0.000022	-	F	65040	65040	0	0	F	-	-	-	-	-	-	-
1575573055.515049	FYXjlFG0LU4PmVdYg	127.0.0.1	127.0.0.1	CkR78y4iZthV0JG12d	HTTP	0	(empty)	application/x-mach-o-executable	-	0.000056	-	F	59088	59088	0	0	F	-	-	-	-	-	-	-
1575573055.533650	F3tpQ24gwPmAINB1ri	127.0.0.1	127.0.0.1	CfM26812zjHVjgdcH5	HTTP	0	PE	application/x-dosexec	-	0.000000	-	F	6656	6656	0	0	F	-	-	-	-	-	-	-
1575573055.549630	FId7Y313XTAGt3u333	127.0.0.1	127.0.0.1	CTFtM72LW5cHoPHXwg	HTTP	0	PE	application/x-dosexec	-	0.006863	-	F	345088	345088	0	0	F	-	-	-	-	-	-	-
1575573055.572433	Fg4xin2mdkzOE1JrJk	127.0.0.1	127.0.0.1	CTj0lp40ja1F2yVI23	HTTP	0	PE	application/x-dosexec	-	0.004190	-	F	301568	301568	0	0	F	-	-	-	-	-	-	-
1575573055.593431	FAoNZT3AgAf5H3hzg2	127.0.0.1	127.0.0.1	CsoGbv4PrzRBIhomG4	HTTP	0	PE	application/x-dosexec	-	0.001843	-	F	135197	135197	0	0	F	-	-	-	-	-	-	-
1575573055.610819	FPxiZq2WmMpcqRuJhe	127.0.0.1	127.0.0.1	CGpVX51GguXN5TpCy3	HTTP	0	PE	application/x-dosexec	-	0.016037	-	F	1160718	1160718	0	0	F	-	-	-	-	-	-	-
#close	2019-12-16-07-20-46

% cat elf.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	elf
#open	2019-12-16-07-20-46
#fields	ts	id	signature	cpu_class	endianness	ver	osabi	abiversion	unused_1	file_type	machine	version	entry	phoff	shoff	flags	ehsize	phentsize	phnum	shentsize	shnum	shstrndx
#types	time	string	count	string	string	count	string	count	string	string	string	count	count	count	count	count	count	count	count	count	count	count
1575573054.870413	Ff9tRIJzK5SSo0Mfe	2135247942	64-bits	Little	1	FreeBSD	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	x86-64	1	4196880	64	6296	0	64	56	8	64	28	27
1575573054.884851	FOYYch36HZTvrQPlTi	2135247942	32-bits	Big	1	HP-UX	1	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	IA-64	1	67607184	52	2572452	8	52	32	12	40	37	36
1575573054.945714	FPx37D1lITkX5Ihrx5	2135247942	32-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_DYN	x86	1	18688	52	152364	0	52	32	5	40	26	23
1575573054.960002	FfTba01VvghPWqT3Gc	2135247942	32-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_DYN	x86	1	217275	52	716804	0	52	32	3	40	27	26
1575573054.985255	Fhtxt04pKjMXuz3xkg	2135247942	64-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	AArch64	1	4319080	64	845672	0	64	56	7	64	27	26
1575573055.014785	FiQK8tHSTDLqHj481	2135247942	32-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	ARM	1	49768	52	89688	83886082	52	32	8	40	28	27
1575573055.029562	F7ydFjDejfkK5p93g	2135247942	64-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	unknown-36902	1	4831943696	64	924720	0	64	56	10	64	29	28
1575573055.059888	F61rl1HjvAvod4IKf	2135247942	32-bits	Big	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	MIPS	1	4271968	52	902356	805310727	52	32	9	40	30	29
1575573055.086529	FrniXj4G5FBbipKAXj	2135247942	32-bits	Big	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	PowerPC	1	268532852	52	952788	0	52	32	9	40	31	30
1575573055.111601	Foa6OD353qEAod1Rtd	2135247942	32-bits	Big	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	unknown-18	1	174720	52	855376	256	52	32	9	40	28	27
1575573055.136312	FlQg1C3yoYu4Ii79G1	2135247942	32-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	SuperH	1	4293024	52	691984	23	52	32	10	40	26	25
1575573055.158362	FDpoEk1h413vhqsAY7	2135247942	32-bits	Big	1	Linux	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	unknown-15	1	162776	52	769272	528	52	32	8	40	28	27
1575573055.180801	FfJxYq2UH8pobDAyh	2135247942	64-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	IA-64	1	4611686018427523264	64	1484232	16	64	56	9	64	33	32
1575573055.219834	FJCWvz4H8NXellwgQg	2135247942	64-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_DYN	x86-64	1	88160	64	1144280	0	64	56	7	64	26	25
1575573055.258825	FD0tNZ191kLavvTgy8	2135247942	32-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_DYN	x86	1	48976	52	1133116	0	52	32	7	40	25	24
1575573055.297420	F5xbP13O6XYTMLgcma	2135247942	64-bits	Big	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	S390	1	2147605336	64	849800	0	64	56	10	64	26	25
1575573055.329918	FxsJOG1mVPjddyfuSe	2135247942	64-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	x86-64	1	4321296	64	924744	0	64	56	8	64	28	27
1575573055.369187	FsZcQB8W5LMIbZCA1	2135247942	32-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	x86	1	134619472	52	810036	0	52	32	8	40	28	27
1575573055.398939	FZhVgl2N790Dfa2FFa	2135247942	64-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_DYN	x86-64	1	2240	64	7440	0	64	56	8	64	33	30
1575573055.415558	FoAJTP3Sasv7vDJRW7	2135247942	64-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_DYN	x86-64	1	848	64	562400	0	64	56	9	64	24	23
1575573055.441153	FlRQhc4ipvfl75f289	2135247942	32-bits	Big	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	SPARC	1	77096	52	399916	0	52	32	5	40	38	37
1575573055.463867	FkwXG93nBmzNl2DOyj	2135247942	32-bits	Little	1	System V	0	\x00\x00\x00\x00\x00\x00\x00	ET_EXEC	x86	1	134519344	52	416436	0	52	32	5	40	37	34
#close	2019-12-16-07-20-46
```

Enjoy!

## License:

Copyright (c) 2019, Corelight, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

(1) Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

(2) Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.

(3) Neither the name of Corelight nor the names of any contributors
    may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
