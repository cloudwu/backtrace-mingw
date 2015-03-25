After we publish an application complied with MinGW-win32 , sometimes we need stack backtrace info when the application crash .

It's very useful for debugging.

The GNU C Library offers backtrace in linux , but MinGW doesn't provide it.

So I wrote this . It's easy to use . Compile it to a DLL , and call LoadLibraryA with it at the beginning of your program.

It will hooks the unhandled exception to output the stack backtrace info to stderr .