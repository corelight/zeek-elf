# @TEST-EXEC: zeek -NN Zeek::ELF |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
