# Computer-virus-technology
0x0 shellcode writing
    1.编写一段弹窗shellcode，这段shellcode要求能独立的调用MessageBoxA函数，而不是依赖程序的导入表(借助GetProcAddress()，LoadLibrary())。
      这里触类旁通，用此方法可以执行任意函数。
    2.并将其注入到calc.exe进程中
    3.最后编写exploit.exe可直接运行注入。
    4.最终效果：运行exploit.exe可直接完成注入，利用calc.exe的进程完成弹窗。
