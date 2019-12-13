# @TEST-EXEC: zeek -NN Zeek::MACHO |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
