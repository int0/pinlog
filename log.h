#pragma once

class CLog
{
private:
	void *_FileHandle;
public:
	CLog();
	~CLog();	
	bool OpenLog( char *filename );
	void CloseLog();
	void Print( const char *format, ... );
};

typedef struct _API_ARGS_FORMAT
{
	char ApiName[250];
	char ApiArgFormat[512];
} API_ARGS_FORMAT, *PAPI_ARGS_FORMAT;

typedef struct _API_ARGS_ARRAY
{
	unsigned int Count;
	API_ARGS_FORMAT a[1];
} API_ARGS_ARRAY, *PAPI_ARGS_ARRAY;

extern CLog *pLog;

void FormatArguments( char *buffer, char *format, void *args );
void LoadApiArgsFormat();
API_ARGS_FORMAT *FindFormatByName( const char *ApiName );