void o0o0o0o0();
void pop(int reg){};
void push(int reg){};
void store(int reg){};
void load(int reg){};
void add(int reg, int val){};
void min(int reg, int val){};

void o0o0o0o0(){
	add(1, 0x77E100);
	load(1);
	add(2, 0x52290);
	store(1);
}

void sh(){};
