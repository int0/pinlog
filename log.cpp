#include <Windows.h>
#include <stdio.h>
#include "log.h"
#include <stdlib.h>

CLog::CLog()
{
	_FileHandle = NULL;
}

CLog::~CLog()
{
	CloseLog();
}

void writeinfo(HANDLE file, const char *format, va_list marker)
{
	char buf[2048], *pos = buf;

	pos += vsprintf(pos, format, marker);

	DWORD written;
	WriteFile(file, buf, pos - buf, &written, NULL);
}

void CLog::Print( const char *format, ... )
{
	if( _FileHandle != NULL && _FileHandle != INVALID_HANDLE_VALUE )
	{
		va_list marker;
		va_start(marker, format);
		writeinfo(_FileHandle, format, marker);
		va_end(marker);
	}
}

bool CLog::OpenLog( char *filename )
{
	_FileHandle = CreateFileA( filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
	return ( _FileHandle != INVALID_HANDLE_VALUE );
}

void CLog::CloseLog()
{
	CloseHandle( _FileHandle );
}


void FormatArguments( char *buffer, char *format, void *args )
{
	va_list marker = (va_list)args;
	vsprintf( buffer, format, marker );	
}

static API_ARGS_ARRAY *ArgFmt;

void LoadApiArgsFormat()
{
	FILE *f = fopen( "apiargs.txt", "rt" );

	if( f == NULL )
		return;	

	char ApiName[250];
	char ApiArgs[512];

	ArgFmt = (API_ARGS_ARRAY *)malloc( sizeof(*ArgFmt) * 5000 );
	memset( ArgFmt, 0, sizeof(*ArgFmt) * 5000 );

	if( f != NULL )
	{
		while( !feof( f ) )
		{
			ApiArgs[0] = 0;
			ApiName[0] = 0;

			fscanf( f, "%s\t\"%[^\"]\"", &ApiName, &ApiArgs );
			strcpy( ArgFmt->a[ArgFmt->Count].ApiName, ApiName );
			strcpy( ArgFmt->a[ArgFmt->Count].ApiArgFormat, ApiArgs );
			ArgFmt->Count++;
		}		
	}

	fclose(f);
}

API_ARGS_FORMAT *FindFormatByName( const char *ApiName )
{
	if( ArgFmt == NULL )
		return NULL;

	for ( unsigned int i = 0; i < ArgFmt->Count; i++ )
	{
		//pLog->Print( "find = %s\n", ApiName );
		if( strcmp( ArgFmt->a[i].ApiName, ApiName ) == 0 )
		{
			return &ArgFmt->a[i];
		}
	}

	return NULL;
}
