#include "pin.H"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <stdio.h>
#include <process.h>
#include <stdlib.h>
#include "log.h"

namespace WIN
{
	#include <windows.h>
}

typedef void (__stdcall *OnApiCallback_t)( const char *ApiName, void *BasePtr, void *StackPtr );

OnApiCallback_t OnApiCallback;

CLog *pLog;
volatile long gLock;

BOOL LogApis = TRUE;
ADDRINT UnlockAt = 0;

bool StartApiLogging = false;
bool LogSyscalls = false;
PIN_LOCK lock;

void LockRoutine()
{
	long  l;
	do 
	{
		l = WIN::InterlockedCompareExchange( &gLock, 1, 0 );
	} while ( l );
}

void UnlockRoutine()
{
	if( gLock )
	{
		WIN::InterlockedDecrement( &gLock );
	}	
}

KNOB<BOOL> KnobLogSyscalls(KNOB_MODE_WRITEONCE, "pintool", "syscall", "0", "log syscall");

void ProtectionFlagsToString( __in UINT32 Flags, __out CHAR *String );


INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	PIN_LockClient();
	
	ADDRINT a = PIN_GetContextReg( ctxt, REG_INST_PTR );
	RTN r = RTN_FindByAddress( a );
	if( RTN_Valid( r ) )
	{
		pLog->Print( "New thread (%d|%x) %x %s\n", threadIndex, threadIndex, a, RTN_Name(r).c_str() );
	}
	else
	{
		pLog->Print( "New thread (%d|%x) %08x\n", threadIndex, threadIndex, a );
	}
	
	PIN_UnlockClient();
}

BOOL FollowChild(CHILD_PROCESS childProcess, VOID * userData)
{
	//INT appArgc;
	//CHAR const * const * appArgv;
	OS_PROCESS_ID pid = CHILD_PROCESS_GetId(childProcess);
	pLog->Print( "child process: %d\n", pid );

// 	CHILD_PROCESS_GetCommandLine(childProcess, &appArgc, &appArgv);
// 
// 	//Inject only if the KnobChildApplicationName value is current child process application
// 	string childAppToInject = KnobChildApplicationName.Value();
// 	string childApp(appArgv[0]);
// 	string::size_type index = childApp.find(childAppToInject);
// 	if(index == string::npos)
// 	{
// 		return FALSE;
// 	}
// 
// 	//Set Pin's command line for child process
// 	INT pinArgc = 0;
// 	CHAR const * pinArgv[10];
// 
// 	string pin = KnobPinFullPath.Value() + "pin";
// 	pinArgv[pinArgc++] = pin.c_str();
// 	pinArgv[pinArgc++] = "-follow_execv";
// 	if (KnobProbeChild)
// 	{
// 		pinArgv[pinArgc++] = "-probe"; // pin in probe mode
// 	}
// 	pinArgv[pinArgc++] = "-t";
// 	string tool = KnobToolsFullPath.Value() + KnobChildToolName.Value();
// 	pinArgv[pinArgc++] = tool.c_str();
// 	pinArgv[pinArgc++] = "-pin_path";
// 	pinArgv[pinArgc++] = KnobPinFullPath.Value().c_str();
// 	pinArgv[pinArgc++] = "-tools_path";
// 	pinArgv[pinArgc++] = KnobToolsFullPath.Value().c_str();
// 	pinArgv[pinArgc++] = "--";
// 
// 	CHILD_PROCESS_SetPinCommandLine(childProcess, pinArgc, pinArgv);

	return TRUE;
}

VOID ImageLoad(IMG img, VOID *v)
{
	pLog->Print( "Load %p %s\n", IMG_LoadOffset(img), IMG_Name(img).c_str() );
}

// Pin calls this function every time a new img is unloaded
// You can't instrument an image that is about to be unloaded
VOID ImageUnload(IMG img, VOID *v)
{
	pLog->Print( "Unload %p %s\n", IMG_LoadOffset(img), IMG_Name(img).c_str());
}

VOID VallocBefore( ADDRINT size)
{
	pLog->Print( "VirtualAlloc(%x) = ", size );
}

VOID VallocAfter(ADDRINT ret)
{
	pLog->Print( "%x\n", ret );
}

VOID GetProcAddrBefore( ADDRINT Module, ADDRINT ApiName )
{
	pLog->Print( "GetProcAddress( %08x, %s )\n", Module, (char *)ApiName );
}

// VOID VirtualProtectBefore( ADDRINT ReturnAddress, ADDRINT Address, ADDRINT Size, ADDRINT Protection )
// {
// 	CHAR P[512];
// 	ProtectionFlagsToString( Protection, P );
// 	pLog->Print( "%08x VirtualProtect( %08x, %-8x, %04x (%s) )\n", ReturnAddress, Address, Size, Protection, P );
// }

void ProtectionFlagsToString( __in UINT32 Flags, __out CHAR *String )
{
	String[0] = 0;

	while ( Flags )
	{
		if( Flags & 0x01 )
		{
			strcat( String, "PAGE_NOACCESS " );
			Flags = Flags & ~0x1;
			continue;
		}

		if( Flags & 0x02 )
		{
			strcat( String, "PAGE_READONLY " );
			Flags = Flags & ~0x2;
			continue;
		}

		if( Flags & 0x04 )
		{
			strcat( String, "PAGE_READWRITE " );
			Flags = Flags & ~0x4;
			continue;
		}

		if( Flags & 0x08 )
		{
			strcat( String, "PAGE_WRITECOPY " );
			Flags = Flags & ~0x8;
			continue;
		}

		if( Flags & 0x10 )
		{
			strcat( String, "PAGE_EXECUTE " );
			Flags = Flags & ~0x10;
			continue;
		}

		if( Flags & 0x20 )
		{
			strcat( String, "PAGE_EXECUTE_READ " );
			Flags = Flags & ~0x20;
			continue;
		}

		if( Flags & 0x40 )
		{
			strcat( String, "PAGE_EXECUTE_READWRITE " );
			Flags = Flags & ~0x40;
			continue;
		}

		if( Flags & 0x80 )
		{
			strcat( String, "PAGE_EXECUTE_WRITECOPY " );
			Flags = Flags & ~0x80;
			continue;
		}

		if( Flags & 0x100 )
		{
			strcat( String, "PAGE_GUARD " );
			Flags = Flags & ~0x100;
			continue;
		}

		if( Flags & 0x200 )
		{
			strcat( String, "PAGE_NOCACHE " );
			Flags = Flags & ~0x200;
			continue;
		}

		if( Flags & 0x400 )
		{
			strcat( String, "PAGE_WRITECOMBINE " );
			Flags = Flags & ~0x400;
			continue;
		}

		pLog->Print( "FailFlags: %x\n", Flags );
		break;
	}

}

// VOID SetupApiHooks(IMG img, VOID *v)
// {
// 	RTN vallocRtn = RTN_FindByName(img, "VirtualAlloc");
// 
// 	if (RTN_Valid(vallocRtn))
// 	{
// 		RTN_Open(vallocRtn);
// 
// 		RTN_InsertCall(vallocRtn, IPOINT_BEFORE, (AFUNPTR)VallocBefore,
// 			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
// 			IARG_END);
// 
// 		RTN_InsertCall(vallocRtn, IPOINT_AFTER, (AFUNPTR)VallocAfter,
// 			IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
// 
// 		RTN_Close(vallocRtn);
// 	}	
// 
// 	RTN gpaRtn = RTN_FindByName(img, "GetProcAddress");
// 	
// 	if( RTN_Valid( gpaRtn ) )
// 	{
// 		RTN_Open( gpaRtn );
// 		
// 		//
// 		// Insert hook before GetProcAddress
// 		//
// 		RTN_InsertCall(gpaRtn, IPOINT_BEFORE, (AFUNPTR)GetProcAddrBefore,
// 			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
// 			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
// 			IARG_END);
// 		
// 		RTN_Close( gpaRtn );
// 	}
// 
// 
// 	RTN vpRtn = RTN_FindByName(img, "VirtualProtect");
// 
// 	if( RTN_Valid( vpRtn ) )
// 	{
// 		RTN_Open( vpRtn );
// 
// 		//
// 		// Insert hook before GetProcAddress
// 		//
// 		RTN_InsertCall(vpRtn, IPOINT_BEFORE, (AFUNPTR)VirtualProtectBefore,
// 			IARG_RETURN_IP,
// 			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
// 			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
// 			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
// 			IARG_END);
// 
// 		RTN_Close( vpRtn );
// 	}
// }

VOID OnRetExecution( VOID *ip, ADDRINT ReturnAddress )
{
	PIN_LockClient();

	ADDRINT addr = (ADDRINT)ip;

	std::string FuncName = RTN_FindNameByAddress( addr );

	if( !FuncName.empty() && FuncName.length() )
	{
		IMG img = IMG_FindByAddress( addr );

		if( img != IMG_Invalid() )
		{
			std::string ImagePath = IMG_Name( img );
			size_t i = ImagePath.find_last_of( '\\' );

			pLog->Print( "ret %s!%s (%p) -> %p\n", &ImagePath.c_str()[i+1], FuncName.c_str(), addr, *(ADDRINT *)ReturnAddress );
		}
		else
		{
			pLog->Print( "ret %s (%p) -> %p\n", FuncName.c_str(), addr, *(ADDRINT *)ReturnAddress );
		}			
	}

	PIN_UnlockClient();
}


VOID OnCallExecution( ADDRINT TakenIP, ADDRINT CalledFrom, ADDRINT sp )
{
	PIN_LockClient();

	//ADDRINT TakenIP = (ADDRINT)PIN_GetContextReg( ctx, REG_INST_PTR );

	RTN r = RTN_FindByAddress( TakenIP );
	IMG img = IMG_FindByAddress( TakenIP );

	if( r != RTN_Invalid() && img != IMG_Invalid() )
	{
		std::string RoutineName;// = RTN_Name( r );
		SYM RoutineSym = RTN_Sym( r );

		if( RoutineSym != SYM_Invalid() )
		{
			RoutineName = SYM_Name( RoutineSym );

			if( !RoutineName.empty() && RoutineName.length() )
			{
				pLog->Print( "- %s\n", RoutineName.c_str() );
			}
		}

	}

	std::string s = RTN_FindNameByAddress( TakenIP );
	

	if( !s.empty() && s.length() )
	{
		

		if( img != IMG_Invalid() )
		{
			std::string ImagePath = IMG_Name( img );
			size_t i = ImagePath.find_last_of( '\\' );

			pLog->Print( "%-32s ! %-64s() (%p)\n", &ImagePath.c_str()[i+1], s.c_str(), TakenIP );
		}
		else
		{
			pLog->Print( "- %-32s() (%p)\n", s.c_str(), TakenIP );
		}			
	}


	PIN_UnlockClient();
}

VOID OnDirectBranchExecution( const CONTEXT *cctx, ADDRINT CalledFrom, ADDRINT sp )
{
	PIN_LockClient();
	ADDRINT ip = PIN_GetContextReg( cctx, REG_INST_PTR );
	//IMG img = IMG_FindByAddress( ip );
	RTN rtn = RTN_FindByAddress( ip );
	SYM sym = RTN_Sym( rtn );
	if( RTN_Valid( rtn ) && SYM_Valid(sym) && !SYM_Dynamic( sym ) )
	{
		pLog->Print( "%p call %-32s() (%p) called from: %p\n", CalledFrom, SYM_Name(sym).c_str(), ip, *(ADDRINT *)sp ); 
	}

	PIN_UnlockClient();
}

bool IsPreviousSysenter = false;

VOID OnSyscallEnter(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	if( StartApiLogging )
	{		
		PIN_LockClient();
		ADDRINT sp = PIN_GetContextReg( ctxt, REG_STACK_PTR );
		ADDRINT bp = PIN_GetContextReg( ctxt, REG_EBP );
		ADDRINT Address = PIN_GetContextReg( ctxt, REG_INST_PTR );
		bool x64 = false;
		// check if far jump (wow64)
		
		if( *(unsigned char *)Address == 0xEA || *(unsigned short *)Address == 0x340F || *(unsigned short *)Address == 0x2ecd )
		{
			Address = *(ADDRINT *)sp;
			x64 = true;
		}

		RTN rtn = RTN_FindByAddress( Address );		
		

		ADDRINT SyscallNum = PIN_GetSyscallNumber( ctxt, std );
		
		if( !LogApis )
		{
			if( !IsPreviousSysenter ) pLog->Print( "\n" );
			pLog->Print( "  " );
		}

		IMG img = IMG_FindByAddress( Address );

		const char *dllname;

		if( IMG_Valid( img ) )
		{
			std::string ImagePath = IMG_Name( img );
			size_t i = ImagePath.find_last_of( '\\' );
			dllname = &ImagePath.c_str()[i+1];
		}
		else
		{
			dllname = "unk";
		}

		if( RTN_Valid( rtn ) )
		{
			const char *ApiName = RTN_Name( rtn ).c_str();

			API_ARGS_FORMAT *afmt =	FindFormatByName( ApiName );

			if( afmt )
			{
				char Args[0x1000];
				void *ArgsPtr = (void *)((x64)? (sp + sizeof(ADDRINT)*2) : (sp + sizeof(ADDRINT)));
				FormatArguments( Args, afmt->ApiArgFormat, ArgsPtr );
				pLog->Print( "%-2d: %p %-12s %p syscall %-5d: %-32s( %s )\n", tid, RTN_Address(rtn), dllname, Address, SyscallNum, ApiName, Args );
			}
			else
			{
				pLog->Print( "%-2d: %p %-12s %p syscall %-5d: %-32s()\n", tid, RTN_Address(rtn), dllname, Address, SyscallNum, ApiName );
			}

			if( OnApiCallback )
			{
				OnApiCallback( ApiName, (void *)bp, (void *)sp );
			}
		}
		else
		{
			pLog->Print( "%-12s syscall %d\n", dllname, SyscallNum );
			
			if( OnApiCallback )
			{
				OnApiCallback( NULL, (void *)bp, (void *)sp );
			}
		}

		PIN_UnlockClient();
	}

	IsPreviousSysenter = true;
}

VOID OnSyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	ADDRINT EAX = PIN_GetContextReg( ctxt, REG_EAX );
	pLog->Print( " returned = 0x%.08x (%d)\n", EAX, EAX );
}

VOID OnRoutineExit( ADDRINT ip, ADDRINT EAX, THREADID tid, ADDRINT UnlockAt )
{
	if( LogApis )
		return;

	pLog->Print( " returned = 0x%.08x (%d)\n", EAX, EAX );
	LogApis = TRUE;

	IsPreviousSysenter = false;

	//ReleaseLock(&lock);
	//PIN_LockClient();
	//UnlockRoutine();
	//PIN_UnlockClient();
}



VOID OnRoutineCall( RTN r, THREADID tid, ADDRINT ip, ADDRINT sp, const CONTEXT *ctx )
{
	IMG img;
	ADDRINT RetAddr = *(ADDRINT *)sp;

	if( !LogApis )
		return;

	if( !StartApiLogging )
	{
		PIN_LockClient();

		img = IMG_FindByAddress( RetAddr );
		
		if( IMG_Valid( img ) && IMG_IsMainExecutable( img ) )
		{
			StartApiLogging = true;
		}

		PIN_UnlockClient();
	}

	if( !StartApiLogging )
		return;
	
	const string s = RTN_Name(r);
	const char *FuncName = s.c_str();

	if( OnApiCallback )
	{
		ADDRINT bp = PIN_GetContextReg( ctx, REG_EBP );
		OnApiCallback( FuncName, (void *)bp, (void *)sp );
	}

	LogApis = FALSE;

	PIN_LockClient();

	img = IMG_FindByAddress( ip );

	PIN_UnlockClient();

	if( IMG_Valid( img ) )
	{
  		std::string ImagePath = IMG_Name( img );
  		size_t i = ImagePath.find_last_of( '\\' );
 		const char *dllname = &ImagePath.c_str()[i+1];

		API_ARGS_FORMAT *afmt =	FindFormatByName( FuncName );
 
 		if( afmt )
 		{
 			char Args[0x1000];
 			FormatArguments( Args, afmt->ApiArgFormat, (void *)(sp+sizeof(ADDRINT)) );
 			pLog->Print( "%-2d: %p <- %-16s %s( %s ) \t", tid, RetAddr, dllname, FuncName, Args );
 		}
 		else
 		{
 			pLog->Print( "%-2d: %p <- %-16s %s \t", tid, RetAddr, dllname, FuncName );
 		}

		UnlockAt = RetAddr;
	}
	else
	{
		LogApis = TRUE;
		//UnlockRoutine();
	}

	IsPreviousSysenter = false;
}

VOID OnRoutine( RTN r, VOID *v )
{
	RTN_Open( r );

	const string s = RTN_Name(r);

	if( !s.empty() )
	{
		INS ins = RTN_InsHead( r );		
		
		RTN_InsertCall( r, IPOINT_BEFORE, (AFUNPTR)OnRoutineCall,  
			IARG_ADDRINT, r,
			IARG_THREAD_ID,
			IARG_INST_PTR,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_CONST_CONTEXT,
			IARG_END );		
	}

	RTN_Close(r);
}

VOID Instruction(INS ins, VOID *v)
{
	if( INS_Address(ins) == UnlockAt )
	{
		//PIN_RemoveInstrumentation();

		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)OnRoutineExit,
			IARG_INST_PTR,
			IARG_REG_VALUE, REG_EAX,
			IARG_THREAD_ID,
			IARG_ADDRINT, UnlockAt,
			IARG_END );		

		UnlockAt = 0;
	}
	
	return;

// 	IMG img = IMG_FindByAddress( INS_Address(ins) );
// 
// 	if( IMG_Valid( img ) && IMG_IsMainExecutable( img ) )
// 	{		
// 		if( IMG_Entry( img ) == INS_Address(ins) )
// 		{
// 			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)StartSysEnterLogging, IARG_END );
// 		}
// 	}
// 
// 
// 	return;
// 
// 
// 	if( INS_IsRet( ins ) )
// 	{
// 		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnRetExecution, IARG_INST_PTR, IARG_REG_VALUE, REG_STACK_PTR, IARG_END );
// 	}
// 	else if( INS_IsBranchOrCall(ins) )
// 	{
// 
// 		if( INS_IsDirectBranchOrCall(ins) )
// 		{
// 			if( INS_IsCall( ins ) )
// 			{
// 
// 			}
// 			else
// 			{
// 
// 			}
// 			INS_InsertCall( ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)OnDirectBranchExecution,
// 				IARG_CONST_CONTEXT,
// 				IARG_ADDRINT, INS_Address(ins),
// 				IARG_REG_VALUE, REG_STACK_PTR,
// 				IARG_END);
// 		}
// 		else
// 		{
// 			INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)OnCallExecution,
// 				IARG_BRANCH_TARGET_ADDR,
// 				IARG_INST_PTR,
// 				IARG_REG_VALUE, REG_STACK_PTR,
// 				IARG_END);
// 		}			
// 
// 
// 
// 	}
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
	if( PIN_Init(argc,argv) )
        return Usage();

	LoadApiArgsFormat();

	if( !PIN_InitSymbolsAlt(EXPORT_SYMBOLS))
		return 0;

	if( KnobLogSyscalls == TRUE )
	{
		LogSyscalls = true;
	}

	// Register ImageLoad to be called when an image is loaded
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// Register ImageUnload to be called when an image is unloaded
	IMG_AddUnloadFunction(ImageUnload, 0);

	//RTN_AddInstrumentFunction(Routine, 0);
    

	INS_AddInstrumentFunction( Instruction, 0 );
	RTN_AddInstrumentFunction( OnRoutine, NULL );

	//IMG_AddInstrumentFunction(SetupApiHooks, 0 );

    // Register function to be called for every thread before it starts running
    //PIN_AddThreadStartFunction(ThreadStart, 0);

	PIN_AddFollowChildProcessFunction( FollowChild, 0 );

	if( LogSyscalls )
	{
		PIN_AddSyscallEntryFunction( OnSyscallEnter, NULL );
		//PIN_AddSyscallExitFunction( OnSyscallExit, NULL );
	}

	WIN::HMODULE hModule = WIN::LoadLibraryA( "pinlog_plug.dll" );
	
	if( hModule )
		OnApiCallback = (OnApiCallback_t)WIN::GetProcAddress( hModule, (WIN::LPCSTR)1 );

 	char LogName[64];
 	pLog = new CLog();	
 	sprintf( LogName, "out_%d_%d.log", WIN::GetCurrentProcessId(), WIN::GetTickCount() );
 	pLog->OpenLog( LogName );

	// Never returns
	if ( PIN_IsProbeMode() )
	{
		PIN_StartProgramProbed();
	}
	else
	{
		PIN_StartProgram();
	}

    return 0;
}