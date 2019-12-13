module MACHO;

@load ./consts

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Current timestamp.
		ts:                  time              	&log;
		## File id of this portable executable file.
		id:                  string            	&log;
		signature:			 string			   	&log &optional;
		is_64bit:			 bool			   	&log &optional;
		little_endian:		 bool			   	&log &optional;
		is_universal_binary: bool			   	&log &optional;
		num_binaries:		 count			   	&log &optional;
		cpu_types:			 vector of string  	&log &optional;
		cpu_subtypes:		 vector of string  	&log &optional;
		image_offsets:		 vector	of count  	&log &optional;
		image_sizes:		 vector	of count	&log &optional;
		filetype:			 string			   	&log &optional;
		ncmds:	  		 	 count			   	&log &optional;
		sizeofcmds:			 count			   	&log &optional;
		flags:			 	 string			   	&log &optional;
	};

	## Event for accessing logged records.
	global log_macho: event(rec: Info);

	## A hook that gets called when we first see a MACHO file.
	global set_file: hook(f: fa_file);
}

redef record fa_file += {
	macho: Info &optional;
};

const macho_mime_types = { "application/x-mach-o-executable" };

event zeek_init() &priority=5
	{
	Files::register_for_mime_types(Files::ANALYZER_MACHO, macho_mime_types);
	Log::create_stream(LOG, [$columns=Info, $ev=log_macho, $path="macho"]);
	}

hook set_file(f: fa_file) &priority=5
	{
	if ( ! f?$macho )
	    {
		f$macho = [$ts=network_time(), $id=f$id];
	    }

	if (! f$macho?$cpu_types)
		{
			f$macho$cpu_types = vector();
		}

	if (! f$macho?$cpu_subtypes)
		{
			f$macho$cpu_subtypes = vector();
		}

	if (! f$macho?$image_offsets)
		{
			f$macho$image_offsets = vector();
		}

	if (! f$macho?$image_sizes)
		{
			f$macho$image_sizes = vector();
		}
    }

event file_macho(f: fa_file) &priority=5
	{
	hook set_file(f);
	}

#
# Good documentation at:
# https://github.com/llvm/llvm-project/blob/master/llvm/include/llvm/BinaryFormat/MachO.h
# https://opensource.apple.com/source/xnu/xnu-792.6.76/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
# https://github.com/aidansteele/osx-abi-macho-file-format-reference
#
event file_macho_header_raw(f: fa_file, m: Zeek::MACHOHeaderRaw) &priority=5
    {
	hook set_file(f);

	# Check for 64 bit
	if (m$signature == hexstr_to_bytestring("FEEDFACF") || m$signature == hexstr_to_bytestring("CFFAEDFE") ||
	    m$signature == hexstr_to_bytestring("CAFEBABF") || m$signature == hexstr_to_bytestring("BFBAFECA"))
		{
		f$macho$is_64bit = T;
		}
	else
		{
		f$macho$is_64bit = F;
		}

	# Check for universal binary
	if (m$signature == hexstr_to_bytestring("CAFEBABE") || m$signature == hexstr_to_bytestring("BEBAFECA") ||
	    m$signature == hexstr_to_bytestring("CAFEBABF") || m$signature == hexstr_to_bytestring("BFBAFECA"))
		{
		f$macho$is_universal_binary = T;
		}
	else
		{
		f$macho$is_universal_binary = F;
		}

	# Check for byte order
	if (m$signature == hexstr_to_bytestring("CEFAEDFE") || m$signature == hexstr_to_bytestring("CFFAEDFE") ||
	    m$signature == hexstr_to_bytestring("BEBAFECA") || m$signature == hexstr_to_bytestring("BFBAFECA"))
		{
		f$macho$little_endian = T;
		f$macho$signature = "0x"+to_upper(bytestring_to_hexstr(reverse(m$signature)));
		}
	else
		{
		f$macho$little_endian = F;
		f$macho$signature = "0x"+to_upper(bytestring_to_hexstr(m$signature));
		}

	if (f$macho$is_universal_binary == T)
		{
		event file_macho_universal_binary(f, m);
		}
		else
		{
		event file_macho_single_binary(f,m);
		}
    }

event file_macho_single_binary(f: fa_file, m: Zeek::MACHOHeaderRaw) &priority=5
	{
	hook set_file(f);

	local cpu_type:			string;
	local cpu_subtype:		string;
	local filetype:			string;
	local ncmds:			string;
	local sizeofcmds:		string;
	local flags:			string;

	cpu_type = m$data[0:4];
	cpu_subtype = m$data[4:8];
	filetype = m$data[8:12];
	ncmds = m$data[12:16];
	sizeofcmds = m$data[16:20];
	flags = m$data[20:24];

	if (f$macho$little_endian == T)
		{
		cpu_type = reverse(cpu_type);
		cpu_subtype = reverse(cpu_subtype);
		filetype = reverse(filetype);
		ncmds = reverse(ncmds);
		sizeofcmds = reverse(sizeofcmds);
		flags = reverse(flags);
		}

	f$macho$cpu_types += cpu_types[bytestring_to_count(cpu_type)];

	switch (cpu_types[bytestring_to_count(cpu_type)])
		{
		case "ARM":
			f$macho$cpu_subtypes += ARMsubtypes[bytestring_to_count(cpu_subtype) & 0xFFFFFF];
			break;
		case "ARM64":
			f$macho$cpu_subtypes += ARM64subtypes[bytestring_to_count(cpu_subtype) & 0xFFFFFF];
			break;
		case "ARM64_32":
			f$macho$cpu_subtypes += ARM64_32subtypes[bytestring_to_count(cpu_subtype) & 0xFFFFFF];
			break;
		case "x86_64":
			f$macho$cpu_subtypes += x86_64subtypes[bytestring_to_count(cpu_subtype) & 0xFFFFFF];
			break;
		case "x86":
			f$macho$cpu_subtypes += x86subtypes[bytestring_to_count(cpu_subtype) & 0xFFFFFF];
			break;
		case "POWERPC":
			f$macho$cpu_subtypes += PowerPCsubtypes[bytestring_to_count(cpu_subtype) & 0xFFFFFF];
			break;
		default:
			f$macho$cpu_subtypes += fmt("unknown-%d", bytestring_to_count(cpu_subtype));
			break;
		}

	f$macho$filetype = filetypes[bytestring_to_count(filetype)];
	f$macho$ncmds = bytestring_to_count(ncmds);
	f$macho$sizeofcmds = bytestring_to_count(sizeofcmds);
	f$macho$flags = "0x"+to_upper(bytestring_to_hexstr(flags));

	local cmd_num = 0;
	local offset: count;

	# Skip over the static fields we already read
	if (f$macho$is_64bit == T)
		{
		offset = 28;
		}
	else
		{
		offset = 24;
		}

	while (offset < 5000 && cmd_num < f$macho$ncmds)
		{
		cmd_num = cmd_num + 1;

		local machocommanddata: Zeek::MACHOCommandData;

		local cmd: count;
		local cmdsize: count;
		local restofdata: string;

		# These are in every section
		cmd = bytestring_to_count(m$data[offset:offset+4], f$macho$little_endian);
		cmdsize = bytestring_to_count(m$data[offset+4:offset+8], f$macho$little_endian);
		restofdata = m$data[offset:offset+cmdsize];
		machocommanddata$cmd = cmd;
		machocommanddata$cmdsize = cmdsize;
		machocommanddata$data = restofdata;

		# Let the next event take care of it from here...
		event file_macho_single_binary_command_raw(f, m, cmd_num, offset, copy(machocommanddata));

		offset = offset + cmdsize;
		}
	}

event file_macho_universal_binary(f: fa_file, m: Zeek::MACHOHeaderRaw) &priority=5
	{
	hook set_file(f);

	f$macho$num_binaries = bytestring_to_count(m$data[0:4], f$macho$little_endian);

	# Read each FAT arch record (different for 32/64 bits)
	local bin_num: count = 0;
	local offs: count = 4;
	while (bin_num < f$macho$num_binaries && offs < 5004)
		{
		local cpu_type: count;
		local cpu_subtype: count;
		local offset: count;
		local size: count;
		local align: count;
		local reserved: count;
		local jump_size: count;

		local machofatarch: Zeek::MACHOFATArch;

		cpu_type = bytestring_to_count(m$data[offs:offs+4], f$macho$little_endian);
		cpu_subtype = bytestring_to_count(m$data[offs+4:offs+8], f$macho$little_endian);
		machofatarch$cpu_type = cpu_type;
		machofatarch$cpu_subtype = cpu_subtype;

		if (f$macho$is_64bit == T)
			{
			offset = bytestring_to_count(m$data[offs+8:offs+16], f$macho$little_endian);
			size = bytestring_to_count(m$data[offs+16:offs+24], f$macho$little_endian);
			align = bytestring_to_count(m$data[offs+24:offs+28], f$macho$little_endian);
			reserved = bytestring_to_count(m$data[offs+28:offs+32], f$macho$little_endian);
			machofatarch$reserved = reserved;
			jump_size = 32;
			}
		else
			{
			offset = bytestring_to_count(m$data[offs+8:offs+12], f$macho$little_endian);
			size = bytestring_to_count(m$data[offs+12:offs+16], f$macho$little_endian);
			align = bytestring_to_count(m$data[offs+16:offs+20], f$macho$little_endian);
			jump_size = 20;
			}

		machofatarch$offset = offset;
		machofatarch$size = size;
		machofatarch$align = align;

		event file_macho_universal_binary_arch(f, m, copy(machofatarch));

		offs = offs + jump_size;
		bin_num = bin_num + 1;
		}
	}

event file_macho_universal_binary_arch(f: fa_file, m: Zeek::MACHOHeaderRaw, a: Zeek::MACHOFATArch) &priority=5
	{
	hook set_file(f);

	local my_type: string = cpu_types[a$cpu_type];
	local my_subtype: string;

	switch (my_type)
		{
		case "ARM":
			my_subtype = ARMsubtypes[a$cpu_subtype & 0xFFFFFF];
			break;
		case "ARM64":
			my_subtype = ARM64subtypes[a$cpu_subtype & 0xFFFFFF];
			break;
		case "ARM64_32":
			my_subtype = ARM64_32subtypes[a$cpu_subtype & 0xFFFFFF];
			break;
		case "x86_64":
			my_subtype = x86_64subtypes[a$cpu_subtype & 0xFFFFFF];
			break;
		case "x86":
			my_subtype = x86subtypes[a$cpu_subtype & 0xFFFFFF];
			break;
		case "POWERPC":
			my_subtype = PowerPCsubtypes[a$cpu_subtype & 0xFFFFFF];
			break;
		default:
			my_subtype = fmt("unknown-%d", a$cpu_subtype);
			break;
		}
	f$macho$cpu_types += my_type;
	f$macho$cpu_subtypes += my_subtype;
	f$macho$image_offsets += a$offset;
	f$macho$image_sizes += a$size;
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( f?$macho )
	    {
		Log::write(LOG, f$macho);
		}
	}