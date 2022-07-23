int test(int a){
	a += 0x12345678;
	a -= 0x87654321;
	a += 0xDEADBEEF;
	a -= 0xCAFEBABE;
	a -= 0xB00DD00D;
	a += 0xFEEDBABE;
	return a;
}
