int main()
{
	__asm
	{
		//获取kernel32.dll的基址

		xor ecx, ecx
		mov eax, fs: [ecx + 0x30] ;//EAX = PEB
		mov eax, [eax + 0xc];//EAX = PEB->Ldr
		mov esi, [eax + 0x14];//ESI = PEB->Ldr.InMemOrder
		lodsd;//EAX = Second module
		xchg eax, esi;//EAX = ESI, ESI = EAX
		lodsd;//EAX = Third(kernel32)
		mov ebx, [eax + 0x10];//EBX = Base address


		//获取导出函数名称va
		mov edx, [ebx + 0x3c];//EDX = DOS->e_lfanew
		add edx, ebx;//EDX = PE Header
		mov edx, [edx + 0x78];//EDX = Offset export table
		add edx, ebx;//EDX = Export table
		mov esi, [edx + 0x20];//ESI = Offset names table
		add esi, ebx;//ESI = Names table
		xor ecx, ecx;//EXC = 0

		//对比函数名称，得到GetProcAddress函数的序号(ecx)
	Get_Function:
		inc ecx;//Inc rement the ordinal 
		lodsd;//Get name offset 
		add eax, ebx;//Get functionname 
		cmp dword ptr[eax], 0x50746547;//GetP 
		jnz Get_Function;
		cmp dword ptr[eax + 0x4], 0x41636f72;//rocA 
		jnz Get_Function;
		cmp dword ptr[eax + 0x8], 0x65726464;//ddre 
		jnz Get_Function;

		//利用序号，找到GetProcAddress函数地址
		mov esi, [edx + 0x24];//ESI = Offset ordinals
		add esi, ebx;//ESI = ordinals table
		mov cx, [esi + ecx * 2];//CX = Number of function
		dec ecx;
		mov esi, [edx + 0x1c];//ESI = Offset Address table
		add esi, ebx;//ESI = Address table;
		mov edx, [esi + ecx * 4];//EDX = Pointer(offset)
		add edx, ebx;//EDX = GetProcAddress

	//利用GetProcAddress函数找到LoadLibrayA函数地址
		xor ecx, ecx;//ECX = 0
		push ebx;//Kernel32 base address
		push edx;//GetProcAddress
		push ecx;//0
		push 0x41797261;//aryA
		push 0x7262694c;//Libr
		push 0x64616f4c;//Load
		push esp;//"LoadLibraryA"
		push ebx;//Kernel32 base address
		call edx;//GetProcAddress()

	//使用LoadLibraryA函数加载需要的dll文件
		add esp, 0xc;//pop "LoadLibraryA"
		pop ecx;//ECX = 0;
		push eax;//EAX = LoadLibraryA
		push ecx;//"\0"
		mov cx, 0x6c6c;//ll
		push ecx;
		push 0x642e3233;//32.d
		push 0x72657375;//user
		push esp;//"user32.dll"
		call eax;//LoadLibrary("user32.dll")

	//使用GetProcAddress从user32dll中找到需要的函数地址
		add esp, 0x10;//Clean stack
		mov edx, [esp + 0x4];//EDX = GetProcAddress
		xor ecx, ecx;//ECX = 0
		push ecx;
		mov	ecx, 0x6141786f;//oxAa
		push ecx;//MessageBox
		sub dword ptr[esp + 0x3], 0x61;//Remove "a"
		push 0x42656761;//ageB
		push 0x7373654d;//Mess
		push esp;//"MessageBoxA"
		push eax;//user.dll address
		call edx;//GetProcAddress(MessageBoxA)

	//调用MessageBoxA
		add esp, 0x10;//Cleanup stack
		xor ecx, ecx;//ECX = 0
		push 0x6465;
		push 0x6b636168;
		mov ebx, esp;
		push 0x6872;
		push 0x65627963;
		mov ecx, esp;
		push 0x00000000;
		push ebx;
		push ecx;
		push 0x00000000;
		call eax;//MessageBoxA();
	}
}
