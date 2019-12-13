# @TEST-EXEC: zeek -C -r $TRACES/all_executables.pcap %INPUT >macho.out
# @TEST-EXEC: btest-diff macho.out
# @TEST-EXEC: btest-diff macho.log

@load Zeek/MACHO

event file_macho_header_command(f: fa_file, m: Zeek::MACHOHeaderRaw, cmd_num: count, offset: count, c: Zeek::MACHOCommand)
    {
      print "====";
      print offset;
      print cmd_num;
      #print m;
      print c;
      print c$segname;
      print "====";
    }