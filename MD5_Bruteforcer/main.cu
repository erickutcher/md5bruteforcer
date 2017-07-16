/*
	MD5 Bruteforcer is a CUDA based MD5 brute force program.
	Copyright (C) 2016-2017 Eric Kutcher

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <math.h>
#include <time.h>

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include "temperature.h"
#include "big_int.h"
#include "big_int_asm.h"
#include "abv.h"

#include "global.cuh"

#define CONSOLE_BUFFER_SIZE		64

#define ALPHA_NUM( c ) ( c - 0x60 )

HANDLE gh_hashing_event = NULL;


CONSOLE_SCREEN_BUFFER_INFO gh_csbi;
HANDLE gh_hInput = NULL;
HANDLE gh_hOutput = NULL;

wchar_t gh_console_buffer[ CONSOLE_BUFFER_SIZE + 1 ];

char *gh_hash_value = NULL;

unsigned long gh_block_size = 0;
unsigned long gh_thread_size = 0;

unsigned char gh_input_length = 0;
unsigned char gh_character_set[ 256 + 1 ];
unsigned short gh_character_set_size = 0;

unsigned long gh_input_chunk_size = 0;			// Size of the input chunk buffer.
unsigned long long gh_input_chunk_count = 0;	// The number of pregenerated values in the input chunk.

unsigned long gh_buffer_int_count = 0;
unsigned long gh_byte_length = 0;
unsigned long gh_block_a = 0, gh_block_b = 0, gh_thread = 0;

unsigned char gh_status = 0;
bool gh_show_information = false;

unsigned char gh_max_temperature = 90;
unsigned char gh_min_temperature = 65;

bool gh_use_null_bytes = false;

void ( *abv_function[ 2 ] )( ABV *abv ) = { &AppendPadding, &AdjustBitmask };

BOOL WINAPI ConsoleHandler( DWORD signal )
{
    if ( signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT || CTRL_LOGOFF_EVENT || CTRL_SHUTDOWN_EVENT )
	{
		gh_status = 1;
	}

    return TRUE;
}

void ClearConsole( HANDLE hConsole )
{
	COORD write_coord = { 0, 0 };
	DWORD written;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	DWORD length;

	GetConsoleScreenBufferInfo( hConsole, &csbi );

	length = csbi.dwSize.X * csbi.dwSize.Y;

	FillConsoleOutputCharacter( hConsole, ' ', length, write_coord, &written );

	GetConsoleScreenBufferInfo( hConsole, &csbi );

	FillConsoleOutputAttribute( hConsole, csbi.wAttributes, length, write_coord, &written );

	SetConsoleCursorPosition( hConsole, write_coord );
}

void GetIntHash( unsigned int *iHash, char *cHash )
{
	if ( cHash != NULL )
	{
		if ( strlen( cHash ) == 32 )
		{
			char temp;
			char *t_cHash = cHash;

			for ( char i = 0; i < 4; ++i )
			{
				temp = t_cHash[ 8 ];
				t_cHash[ 8 ] = 0;
				iHash[ i ] = _byteswap_ulong( strtoul( t_cHash, NULL, 16 ) );
				t_cHash[ 8 ] = temp;
				t_cHash += 8;
			}
		}
	}
}

unsigned __stdcall BeginBruteForce( LPVOID pArgs )
{
	LARGE_INTEGER pcFrequency, pcStart, pcStop;

	double frequency = 0;

	double current_time = 0;
	double time_elapsed = 0;

	double progress = 0;

	unsigned long long current_hashes_processed = 0;

	BIG_INT bi_total_time;

	COORD ccp = { 0, 0 };

	NvPhysicalGpuHandle physical_gpu_handle = NULL;
	int gpu_temperature = 0;

	bool use_abv = ( gh_input_length > ( gh_buffer_int_count * 4 ) );

	unsigned char adjust_type = ( ( gh_input_length == 6 && gh_buffer_int_count == 1 ) ? 1 : 0 );

	unsigned long hash_function_offset = ( gh_input_length - 1 ) + ( 55 * ( gh_buffer_int_count - 1 ) );
	if ( gh_use_null_bytes )
	{
		hash_function_offset += ( 55 * 6 );
	}

	ABV abv;

	BIG_INT bi_hash_combinations;
	BIG_INT bi_hash_count;

	double total_time = 0;

	unsigned int found_hash_input[ 14 ];

	bool hash_found = false;

	unsigned int hash[ 4 ] = { 0 };

	unsigned char *h_character_set = NULL;

	unsigned int *h_input_chunk = NULL;
	unsigned int *h_reversed_hash_values = NULL;
	unsigned char *h_found_hash_input = NULL;	// Points to a static buffer. Don't free.
	unsigned int *h_input_chunk2 = NULL;

	big_int_init( &bi_hash_count );
	big_int_init( &bi_hash_combinations, ( unsigned long )gh_character_set_size );
	big_int_init( &bi_total_time );

	big_int_pow( &bi_hash_combinations, ( unsigned long )gh_input_length );

	if ( use_abv )
	{
		abv_init( &abv, gh_input_length - ( unsigned char )( gh_buffer_int_count * sizeof( unsigned int ) ), gh_character_set, gh_character_set_size );
	}

	// Convert the hash string into four 32 bit integer.
	GetIntHash( hash, gh_hash_value );

	// Prereverse the hash by subtracting the magic numbers.
	// The addition of these values would have occurred at the end of the hash function.
	hash[ 0 ] -= 0x67452301;
	hash[ 1 ] -= 0xefcdab89;
	hash[ 2 ] -= 0x98badcfe;
	hash[ 3 ] -= 0x10325476;

	cudaMemcpyToSymbol( gd_hash_value, hash, sizeof( unsigned int ) * 4 );

	// Create a dynamic device variable to store our character set.
	cudaMalloc( ( void ** )&h_character_set, sizeof( unsigned char ) * gh_character_set_size );
	cudaMemcpy( h_character_set, gh_character_set, sizeof( unsigned char ) * gh_character_set_size, cudaMemcpyHostToDevice );

	// Copy the pointer to the dynamic device variable to our global (character set) device variable.
	cudaMemcpyToSymbol( gd_character_set, &h_character_set, sizeof( h_character_set ) );

	// Size of the character set.
	cudaMemcpyToSymbol( gd_character_set_size, &gh_character_set_size, sizeof( gh_character_set_size ) );

	cudaMemcpyToSymbol( gd_hash_found, &hash_found, sizeof( hash_found ) );

	// Pregenerated input.
	cudaMalloc( ( void ** )&h_input_chunk, sizeof( unsigned int ) * gh_input_chunk_size * gh_buffer_int_count );
	cudaMemset( h_input_chunk, 0, sizeof( unsigned int ) * gh_input_chunk_size * gh_buffer_int_count );
	cudaMemcpyToSymbol( gd_input_chunk, &h_input_chunk, sizeof( h_input_chunk ) );

	// Incremented input.
	if ( use_abv )
	{
		cudaMalloc( ( void ** )&h_input_chunk2, sizeof( unsigned int ) * abv.size );
		cudaMemset( h_input_chunk2, 0, sizeof( unsigned int ) * abv.size );
		cudaMemcpyToSymbol( gd_input_chunk2, &h_input_chunk2, sizeof( h_input_chunk2 ) );
	}

	// Reversed hash input.
	cudaMalloc( ( void ** )&h_reversed_hash_values, sizeof( unsigned int ) * 4 * gh_character_set_size * gh_character_set_size );
	cudaMemcpyToSymbol( gd_reversed_hash_values, &h_reversed_hash_values, sizeof( h_reversed_hash_values ) );
	
	// The input that matches the hash.
	cudaGetSymbolAddress( ( void ** )&h_found_hash_input, gd_found_hash_input );
	cudaMemset( h_found_hash_input, 0, sizeof( unsigned int ) * 14 );

	// Choose which GPU to run on, change this on a multi-GPU system.
    cudaSetDevice( 0 );

	physical_gpu_handle = GetPhysicalGPUHandle();


	QueryPerformanceFrequency( &pcFrequency );
	frequency = ( double )pcFrequency.QuadPart;

	// We'll set this many bytes.
	unsigned long input_byte_length = ( gh_input_length > ( gh_buffer_int_count * 4 ) ? ( gh_buffer_int_count * 4 ) : gh_input_length );

	GenerateInputChunk<<< dim3( gh_block_a, gh_block_b, 1 ), dim3( gh_thread, 1, 1 ) >>>( gh_buffer_int_count, input_byte_length );
	cudaDeviceSynchronize();

	// Prereverse the hash to use in RHL06B01().
	if ( adjust_type == 1 )
	{
		PreReverseHashInputLength06<<< dim3( gh_character_set_size, 1, 1 ), dim3( gh_character_set_size, 1, 1 ) >>>();
		cudaDeviceSynchronize();
	}

	ClearConsole( gh_hOutput );

	printf( "Ctrl + [p]ause, Ctrl + [n]ew input, Ctrl + [i]nformation, Ctrl + [q]uit\r\n\r\n" );
	printf( "MD5 hash value:\t\t%s\r\n", gh_hash_value );
	printf( "Status:\t\t\tHashing\r\n" );
	printf( "Character set size:\t%lu\r\n", gh_character_set_size );
	printf( "Input length:\t\t%lu\r\n", gh_input_length );
	printf( "Total hash values:\t" );
	big_int_print( &bi_hash_combinations );
	printf( "\r\n" );
	
	if ( gh_show_information )
	{
		printf( "Current inputs hashed:\t0\r\n" );
		printf( "Hashing progress:\t0.0000%%\r\n" );
		printf( "Current hash speed:\t0/sec\r\n" );
		gpu_temperature = GetGPUTemperature( physical_gpu_handle );
		if ( gpu_temperature != -1 )
		{
			if ( gh_max_temperature )
			{
				if ( gpu_temperature >= gh_max_temperature )
				{
					if ( gh_status == 0 )
					{
						gh_status = 2;	// Pause
					}
				}
			}

			printf( "GPU Temperature:\t%d\370C\r\n", gpu_temperature );
		}
		else
		{
			printf( "GPU Temperature:\tN/A\r\n" );
		}
	}

	// This outer loop handles pauses (Ctrl + p, or from temperature monitor).
	while ( true )
	{
		if ( gh_status != 2 )
		{
			ccp.Y = 3;
			SetConsoleCursorPosition( gh_hOutput, ccp );

			printf( "Status:\t\t\tHashing%40s\r\n", "" );
		}

		// This loop generates inputs and runs them through our hash function.
		// It'll exit when an input is found, or if the status changes to paused or stopped.
		while ( !gh_status )
		{
			if ( use_abv )
			{
				abv_function[ adjust_type ]( &abv );

				cudaMemcpy( h_input_chunk2, abv.cval, sizeof( unsigned int ) * abv.size, cudaMemcpyHostToDevice );
			}

			QueryPerformanceCounter( &pcStart );

			hash_function[ hash_function_offset ]<<< gh_block_size, gh_thread_size >>>();

			// Did any of the threads find the hash input? This will also synchronize the device.
			cudaMemcpyFromSymbol( &hash_found, gd_hash_found, sizeof( bool ) );

			QueryPerformanceCounter( &pcStop );
			current_time = ( double )( pcStop.QuadPart - pcStart.QuadPart ) / frequency;
			total_time += current_time;
			time_elapsed += current_time;

			current_hashes_processed += gh_input_chunk_count;

			big_int_add( &bi_hash_count, gh_input_chunk_count );
			big_int_add( &bi_total_time, ( unsigned long long )( current_time * 1000000000.0f ) );	// Adjust the precision.

			// Exit the input/hash loop if we found the hash input.
			if ( hash_found )
			{
				break;
			}

			// Update progress information every 2 seconds (or roughly 2 seconds).
			if ( time_elapsed >= 2.0f )
			{
				ccp.Y = 7;
				SetConsoleCursorPosition( gh_hOutput, ccp );

				if ( gh_show_information )
				{
					// This isn't going to be a 100% accurate, but it's close enough.
					progress = big_int_simple_percent( &bi_hash_combinations, &bi_hash_count );
					if ( progress == 1.0f )
					{
						progress = 0.999999f;
					}
					// Add a bunch of spaces so that it erases the previous characters.
					printf( "Current inputs hashed:\t" );
					big_int_print( &bi_hash_count );
					printf( "%40s\r\n", "" );
					printf( "Hashing progress:\t%.4f%%%40s\r\n", 100.0f * progress, "" );
					printf( "Current hash speed:\t%.0f/sec%40s\r\n", current_hashes_processed / time_elapsed, "" );
					gpu_temperature = GetGPUTemperature( physical_gpu_handle );
					if ( gpu_temperature != -1 )
					{
						if ( gh_max_temperature )
						{
							if ( gpu_temperature >= gh_max_temperature )
							{
								if ( gh_status == 0 )
								{
									gh_status = 2;	// Pause
								}
							}
						}

						printf( "GPU Temperature:\t%d\370C%40s\r\n", gpu_temperature, "" );
					}
					else
					{
						printf( "GPU Temperature:\tN/A%40s\r\n", "" );
					}
				}
				else
				{
					printf( "%80s\r\n%80s\r\n%80s\r\n%80s\r\n", "", "", "", "" );
				}

				current_hashes_processed = 0;
				time_elapsed = 0;
			}

			// See if we've incremented to the last value.
			if ( big_int_cmp( &bi_hash_count, &bi_hash_combinations ) != -1 )
			{
				break;
			}

			// Update our arbitrary based value to the next input chunk.
			if ( use_abv )
			{
				abv_increment( &abv );
			}
		}

		ccp.Y = 3;
		SetConsoleCursorPosition( gh_hOutput, ccp );

		printf( "Status:\t\t\t%s%40s\r\n", ( gh_status == 1 ? "Stopped" : ( gh_status == 2 ? "Paused" : "Finished" ) ), "" );

		// If not paused, then display results.
		if ( gh_status != 2 )
		{
			ccp.Y = 7;
			SetConsoleCursorPosition( gh_hOutput, ccp );

			printf( "Total inputs hashed:\t" );
			big_int_print( &bi_hash_count );
			printf( "%40s\r\n", "" );

			progress = big_int_simple_percent( &bi_hash_combinations, &bi_hash_count );
			printf( "Hashing progress:\t%.4f%%%40s\r\n", 100.0f * progress, "" );

			big_int_mul( &bi_hash_count, 1000000000UL );
			big_int_div( &bi_hash_count, &bi_total_time );
			printf( "Average hash speed:\t" );
			big_int_print( &bi_hash_count );
			printf( "/sec%40s\r\n", "" );

			printf( "Elapsed time:\t\t%.6f sec%40s\r\n", total_time, "" );

			printf( "Input result:\t\t" );

			if ( hash_found )
			{
				cudaMemcpyFromSymbol( found_hash_input, gd_found_hash_input, sizeof( unsigned int ) * 14 );

				SetConsoleTextAttribute( gh_hOutput, FOREGROUND_GREEN | FOREGROUND_INTENSITY );

				char *output = ( char * )found_hash_input;
				for ( unsigned short i = 0; i < gh_input_length; ++i )
				{
					if ( isprint( output[ i ] ) )
					{
						printf( "%c", output[ i ] );
					}
					else
					{
						// Set to a darker green to signify a hex value.
						SetConsoleTextAttribute( gh_hOutput, FOREGROUND_GREEN );
						printf( "%02x", output[ i ] );
						SetConsoleTextAttribute( gh_hOutput, FOREGROUND_GREEN | FOREGROUND_INTENSITY );
					}
				}

				SetConsoleTextAttribute( gh_hOutput, gh_csbi.wAttributes );

				printf( "%40s\r\n", "" );
			}
			else
			{
				SetConsoleTextAttribute( gh_hOutput, FOREGROUND_RED | FOREGROUND_INTENSITY );

				printf( "NOT FOUND%40s\r\n", "" );

				SetConsoleTextAttribute( gh_hOutput, gh_csbi.wAttributes );
			}

			break;
		}
		else	// Paused
		{
			ccp.Y = 7;
			SetConsoleCursorPosition( gh_hOutput, ccp );

			if ( gh_show_information )
			{
				// This isn't going to be a 100% accurate, but it's close enough.
				progress = big_int_simple_percent( &bi_hash_combinations, &bi_hash_count );
				if ( progress == 1.0f )
				{
					progress = 0.999999f;
				}
				// Add a bunch of spaces so that it erases the previous characters.
				printf( "Current inputs hashed:\t" );
				big_int_print( &bi_hash_count );
				printf( "%40s\r\n", "" );
				printf( "Hashing progress:\t%.4f%%%40s\r\n", 100.0f * progress, "" );
				printf( "Current hash speed:\t0/sec%40s\r\n", "" );
				gpu_temperature = GetGPUTemperature( physical_gpu_handle );
				if ( gpu_temperature != -1 )
				{
					if ( gh_max_temperature )
					{
						if ( gpu_temperature >= gh_max_temperature )
						{
							if ( gh_status == 0 )
							{
								gh_status = 2;	// Pause
							}
						}
						else if ( gpu_temperature <= gh_min_temperature )
						{
							if ( gh_status == 2 )
							{
								gh_status = 0;	// Resume hashing

								SetEvent( gh_hashing_event );
							}
						}
					}

					printf( "GPU Temperature:\t%d\370C%40s\r\n", gpu_temperature, "" );
				}
				else
				{
					printf( "GPU Temperature:\tN/A%40s\r\n", "" );
				}
			}
			else
			{
				printf( "%80s\r\n%80s\r\n%80s\r\n%80s\r\n", "", "", "", "" );
			}
		}

		// Wait if paused.
		WaitForSingleObject( gh_hashing_event, 2000 );
	}

	// Cleanup our GPU memory.
	if ( h_character_set != NULL )
	{
		cudaFree( h_character_set );
	}

	if ( h_input_chunk != NULL )
	{
		cudaFree( h_input_chunk );
	}

	if ( h_input_chunk2 != NULL )
	{
		cudaFree( h_input_chunk2 );
	}

	if ( h_reversed_hash_values != NULL )
	{
		cudaFree( h_reversed_hash_values );
	}

	// Cleanup our local memory.
	if ( use_abv )
	{
		abv_uninit( &abv );
	}

	big_int_uninit( &bi_hash_count );
	big_int_uninit( &bi_hash_combinations );
	big_int_uninit( &bi_total_time );

	_endthreadex( 0 );
	return 0;
}

bool GetInputValues()
{
	DWORD read = 0;

	char *charset_lc = "abcdefghijklmnopqrstuvwxyz";
	char *charset_uc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char *charset_num = "0123456789";
	char *charset_sym = " !\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";

	int hash_value_length = 0;
	unsigned int input_length = 0;
	unsigned char character_set_type = 0;

	SetConsoleMode( gh_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );


	/////// MD5 Hash Value ///////
	do
	{
		printf( "MD5 hash value: " );
		ReadConsoleW( gh_hInput, gh_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );
		if ( read == 0 ) { return false; }

		if ( read > 2 )
		{
			read -= 2;
		}
	}
	while ( read != 32 );

	gh_console_buffer[ read ] = 0;	// Sanity.

	hash_value_length = WideCharToMultiByte( CP_UTF8, 0, gh_console_buffer, -1, NULL, 0, NULL, NULL );
	gh_hash_value = ( char * )malloc( sizeof( char ) * hash_value_length ); // Size includes the null character.
	WideCharToMultiByte( CP_UTF8, 0, gh_console_buffer, -1, gh_hash_value, hash_value_length, NULL, NULL );
	//////////////////////////////


	//////// INPUT LENGTH ////////
	input_length = 0;
	do
	{
		printf( "Input length (1-55): " );
		ReadConsoleW( gh_hInput, gh_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );
		if ( read == 0 ) { return false; }

		if ( read > 2 )
		{
			read -= 2;

			if ( read <= 2 )
			{
				gh_console_buffer[ read ] = 0;	// Sanity.

				input_length = wcstoul( gh_console_buffer, NULL, 10 );
			}
		}
	}
	while ( input_length < 1 || input_length > 55 );

	gh_input_length = ( unsigned char )input_length;
	//////////////////////////////


	///////// CHARACTER SET /////////
	character_set_type = 0;
	while ( true )
	{
		printf( "Character set.\r\n" \
				"  1: Lowercase letters (a-z)\r\n" \
				"  2: Uppercase letters (A-Z)\r\n" \
				"  3: Numbers (0-9)\r\n" \
				"  4: Symbols\r\n" \
				"  5: ASCII\r\n" \
				"  6: Extended ASCII\r\n" \
				"  7: Custom\r\n" \
				"Selection: " );
		ReadConsoleW( gh_hInput, gh_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );
		if ( read == 0 ) { return false; }

		if ( read > 2 )
		{
			read -= 2;

			if ( read <= 5 )
			{
				while ( read > 0 )
				{
					--read;

					if ( gh_console_buffer[ read ] == '1' )
					{
						character_set_type |= 1;
					}
					else if ( gh_console_buffer[ read ] == '2' )
					{
						character_set_type |= 2;
					}
					else if ( gh_console_buffer[ read ] == '3' )
					{
						character_set_type |= 4;
					}
					else if ( gh_console_buffer[ read ] == '4' )
					{
						character_set_type |= 8;
					}
					else if ( gh_console_buffer[ read ] == '5' )
					{
						character_set_type |= 16;
					}
					else if ( gh_console_buffer[ read ] == '6' )
					{
						character_set_type |= 32;
					}
					else if ( gh_console_buffer[ read ] == '7' )
					{
						character_set_type = 64;
					}
				}

				break;
			}
		}
	}
	//////////////////////////////


	memset( gh_character_set, 0, sizeof( char ) * ( 256 + 1 ) );
	gh_character_set_size = 0;

	gh_use_null_bytes = false;

	if ( character_set_type & 16 )	// ASCII character set.
	{
		for ( unsigned short i = 0; i < 0x80; ++i )
		{
			gh_character_set[ gh_character_set_size + i ] = ( unsigned char )i;
		}

		gh_character_set_size += 0x80;
	}
	else	// If ASCII was set, then these are already in it.
	{
		if ( character_set_type & 1 )	// Lowercase letters.
		{
			memcpy_s( gh_character_set + gh_character_set_size, 256 - gh_character_set_size, charset_lc, 26 );
			gh_character_set_size += 26;
		}

		if ( character_set_type & 2 )	// Uppercase letters.
		{
			memcpy_s( gh_character_set + gh_character_set_size, 256 - gh_character_set_size, charset_uc, 26 );
			gh_character_set_size += 26;
		}

		if ( character_set_type & 4 )	// Numbers.
		{
			memcpy_s( gh_character_set + gh_character_set_size, 256 - gh_character_set_size, charset_num, 10 );
			gh_character_set_size += 10;
		}

		if ( character_set_type & 8 )	// Symbols.
		{
			memcpy_s( gh_character_set + gh_character_set_size, 256 - gh_character_set_size, charset_sym, 33 );
			gh_character_set_size += 33;
		}
	}

	if ( character_set_type & 32 )	// Extended ASCII character set.
	{
		for ( unsigned short i = 0; i < 0x80; ++i )
		{
			gh_character_set[ gh_character_set_size + i ] = ( unsigned char )( 0x80 + i );
		}

		gh_character_set_size += 0x80;
	}

	if ( character_set_type == 64 )	// Custom character set.
	{
		while ( true )
		{
			printf( "Custom character set (in hexadecimal): " );

			wchar_t hex_buffer[ 512 + 3 ];	// 256 hex values max (00, 01, 02, ..., FF) * 2 + /r/n + NULL.
			ReadConsoleW( gh_hInput, hex_buffer, 512 + 3, &read, NULL );
			if ( read == 0 ) { return false; }

			if ( read > 2 )
			{
				read -= 2;

				if ( read <= 512 )
				{
					hex_buffer[ read ] = 0;	// Sanity.

					for ( unsigned short i = 0; i < read; i += 2 )
					{
						wchar_t tmp_hex_char = hex_buffer[ i + 2 ];
						hex_buffer[ i + 2 ] = 0;

						unsigned char custom_character = ( unsigned char )wcstoul( hex_buffer + i, NULL, 16 );
						if ( custom_character == 0 )
						{
							gh_use_null_bytes = true;
						}
						gh_character_set[ gh_character_set_size++ ] = custom_character;

						hex_buffer[ i + 2 ] = tmp_hex_char;
					}

					break;
				}
			}
		}
	}

	gh_character_set[ gh_character_set_size ] = 0;	// Sanity.


	///// SHUFFLE CHARACTER SET /////
	while ( true )
	{
		printf( "Shuffle character set? [Y]es/[N]o: " );
		ReadConsoleW( gh_hInput, gh_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );
		if ( read == 0 ) { return false; }

		if ( read == 3 )
		{
			if ( gh_console_buffer[ 0 ] == 'Y' || gh_console_buffer[ 0 ] == 'y' )
			{
				unsigned char tmp_cs;
				int r1;

				for ( unsigned short i = 0; i < 256; ++i )
				{
					for ( unsigned short j = 0; j < gh_character_set_size; ++j )
					{
						r1 = rand() % gh_character_set_size;

						tmp_cs = gh_character_set[ r1 ];
						gh_character_set[ r1 ] = gh_character_set[ j ];
						gh_character_set[ j ] = tmp_cs;
					}
				}

				break;
			}
			else if ( gh_console_buffer[ 0 ] == 'N' || gh_console_buffer[ 0 ] == 'n' )
			{
				break;
			}
		}
	}
	/////////////////////////////////


	////// MAX GPU TEMPERATURE //////
	while ( true )
	{
		printf( "Maximum GPU temperature (default is 90\370C): " );
		ReadConsoleW( gh_hInput, gh_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );
		if ( read == 0 ) { return false; }

		if ( read >= 2 )
		{
			read -= 2;

			if ( read == 0 )
			{
				gh_max_temperature = 90;
			}
			else if ( read <= 3 )
			{
				gh_console_buffer[ read ] = 0;	// Sanity.

				gh_max_temperature = ( unsigned char )wcstoul( gh_console_buffer, NULL, 10 );
			}

			break;
		}
	}
	//////////////////////////////

	if ( gh_max_temperature == 0 )
	{
		printf( "GPU temperature threshold is disabled.\r\n" );

		gh_min_temperature = 0;
	}
	else
	{
		////// MIN GPU TEMPERATURE //////
		while ( true )
		{
			printf( "Minimum GPU temperature (default is 65\370C): " );
			ReadConsoleW( gh_hInput, gh_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );
			if ( read == 0 ) { return false; }

			if ( read >= 2 )
			{
				read -= 2;

				if ( read == 0 )
				{
					gh_min_temperature = 65;
				}
				else if ( read <= 3 )
				{
					gh_console_buffer[ read ] = 0;	// Sanity.

					gh_min_temperature = ( unsigned char )wcstoul( gh_console_buffer, NULL, 10 );
				}

				if ( gh_min_temperature < gh_max_temperature )
				{
					break;
				}
				else
				{
					printf( "The minimum GPU temperature must be lower than %lu\370C\r\n", gh_max_temperature );
				}
			}
		}
		//////////////////////////////
	}

	return true;
}

void CreateOptimalThreadAndBufferValues()
{
	unsigned short stride_multiple = 32;
	unsigned short stride_size = 0;

	unsigned long long max_size = 32 * 1024 * 1024;	// 32 MB

	unsigned long long chunk_count = 1;

	gh_input_chunk_size = 1;
	gh_input_chunk_count = 1;
	gh_byte_length = 0;

	// Round up to nearest multiple.
	stride_multiple = ( ( gh_character_set_size + 1 ) / 2 ) * 2;
	if ( stride_multiple > 32 )
	{
		stride_multiple = 32;
	}
	stride_size = ( ( gh_character_set_size + stride_multiple - 1 ) / stride_multiple ) * stride_multiple;

	// What's the total number of bytes we can fit our character set into without going over our memory size limit?
	unsigned long long current_size = 1;
	for ( ; gh_byte_length < 64; ++gh_byte_length )
	{
		current_size *= stride_size;

		if ( current_size > max_size )
		{
			break;
		}
	}

	// How many ints does the number of bytes require?
	gh_buffer_int_count = gh_byte_length / sizeof( unsigned long );
	if ( gh_buffer_int_count == 0 )
	{
		gh_buffer_int_count = 1;
	}

	// Adjust the int count and number of bytes required based on the input length.
	unsigned long input_length = ( gh_input_length + ( sizeof( unsigned long ) - 1 ) ) / sizeof( unsigned long );
	if ( gh_buffer_int_count > input_length )
	{
		gh_byte_length = gh_input_length;
		gh_buffer_int_count = input_length;
	}
	else if ( gh_byte_length % sizeof( unsigned long ) != ( sizeof( unsigned long ) - 1 ) )
	{
		gh_byte_length = ( gh_buffer_int_count * sizeof( unsigned long ) ) - 1;
	}

	// Determine the values to raise our character set size to (power of) for the Grid and Block dimensions for GenerateInputChunk().
	gh_thread = gh_byte_length / ( sizeof( unsigned long ) - 1 );

	unsigned char byte_rem = gh_byte_length % ( sizeof( unsigned long ) - 1 );
	if ( byte_rem == 2 )
	{
		gh_block_a = gh_block_b = gh_thread + 1;
	}
	else if ( byte_rem == 1 )
	{
		gh_block_a = gh_block_b = gh_thread;
		++gh_thread;
	}
	else
	{
		gh_block_a = gh_block_b = gh_thread;
	}

	// Determine the chunk size and count based on our adjusted byte length.
	for ( unsigned long i = 0; i < gh_byte_length; ++i )
	{
		gh_input_chunk_size *= stride_size;
		chunk_count *= gh_character_set_size;
	}

	// Grid and Block dimensions for our hashing functions.
	if ( gh_block_a == 1 && gh_block_b == 1 && gh_thread == 1 )
	{
		// Round up to nearest multiple.
		gh_thread_size = ( ( ( gh_character_set_size * 2 ) + stride_multiple - 1 ) / stride_multiple ) * stride_multiple;

		// Round up the block size.
		gh_block_size = ( unsigned long )( chunk_count / gh_thread_size ) + ( ( chunk_count % gh_thread_size ) != 0 );
	}
	else
	{
		gh_block_size = 1;
		gh_thread_size = 0;

		// Max grid size is 65536.
		while ( true )
		{
			if ( chunk_count % gh_block_size == 0 )
			{
				gh_thread_size = ( unsigned long )( chunk_count / gh_block_size );

				// Max block size is 512.
				if ( gh_thread_size <= 512 )
				{
					break;
				}
			}

			if ( gh_block_size < 65536 )
			{
				++gh_block_size;
			}
			else
			{
				break;
			}
		}
	}

	// I've found that a block size and thread size that are near half their max is most efficient.
	if ( gh_thread_size == 512 )
	{
		while ( ( gh_block_size * 2 ) <= 32768 )
		{
			gh_thread_size /= 2;
			gh_block_size *= 2;
		}
	}

	// Grid and Block dimensions for GenerateInputChunk().
	unsigned long gh_bt_tmp = 1;
	for ( unsigned long a = 0; a < gh_block_a; ++a )
	{
		gh_bt_tmp *= gh_character_set_size;
	}
	gh_block_a = gh_bt_tmp;

	gh_bt_tmp = 1;
	for ( unsigned long a = 0; a < gh_block_b; ++a )
	{
		gh_bt_tmp *= gh_character_set_size;
	}
	gh_block_b = gh_bt_tmp;

	gh_bt_tmp = 1;
	for ( unsigned long a = 0; a < gh_thread; ++a )
	{
		gh_bt_tmp *= gh_character_set_size;
	}
	gh_thread = gh_bt_tmp;

	// Determine the number of combinations in our pregenerated input buffer.
	chunk_count = ( gh_byte_length >= gh_input_length ? gh_input_length : ( gh_byte_length + 1 ) );
	for ( unsigned long i = 0; i < chunk_count; ++i )
	{
		gh_input_chunk_count *= gh_character_set_size;
	}
/*
	printf( "Stride size: %lu\r\n" \
	"Input chunk size: %lu\r\n" \
	"Input chunk count: %llu\r\n", stride_size, gh_input_chunk_size, gh_input_chunk_count );

	printf( "Character set size: %lu\r\n" \
	"Block size: %lu\r\n" \
	"Thread size: %lu\r\n", gh_character_set_size, gh_block_size, gh_thread_size );

	printf( "Buffer int count: %lu\r\n" \
	"Byte count: %lu\r\n" \
	"Block A, Block B, Thread: %lu %lu %lu\r\n", gh_buffer_int_count, gh_byte_length, gh_block_a, gh_block_b, gh_thread );

	for ( int i = 0; i < gh_character_set_size; ++i )
	{
		printf( "%x ", gh_character_set[ i ] );
	}
	getchar();
*/
}

int main()
{
	HANDLE hashing_thread = NULL;

	DWORD read = 0;

	CONSOLE_CURSOR_INFO cci;

	// Set our console to receive Ctrl + x key presses.
	CONSOLE_READCONSOLE_CONTROL crcc;
	crcc.nLength = sizeof( CONSOLE_READCONSOLE_CONTROL );
	crcc.nInitialChars = 0;
	crcc.dwCtrlWakeupMask = 0xFFFFFFFF;
	crcc.dwControlKeyState = 0;

	// Seed the prng for character set shuffling.
	srand( ( unsigned int )time( NULL ) );

	gh_hashing_event = CreateEvent( NULL, TRUE, FALSE, NULL );
	if ( gh_hashing_event == NULL )
	{
		printf( "Unable to create event object.\r\n" );

		goto CLEANUP;
	}

	SetConsoleCtrlHandler( ConsoleHandler, TRUE );

	gh_hInput = GetStdHandle( STD_INPUT_HANDLE );

	gh_hOutput = GetStdHandle( STD_OUTPUT_HANDLE );

	GetConsoleScreenBufferInfo( gh_hOutput, &gh_csbi );

	do
	{
		gh_status = 0;	// Begin hashing.

		ClearConsole( gh_hOutput );

		if ( !GetInputValues() )
		{
			goto CLEANUP;
		}

		CreateOptimalThreadAndBufferValues();

		// Hide the console cursor position.
		GetConsoleCursorInfo( gh_hOutput, &cci );
		cci.bVisible = FALSE;
		SetConsoleCursorInfo( gh_hOutput, &cci );

		hashing_thread = ( HANDLE )_beginthreadex( NULL, 0, BeginBruteForce, NULL, 0, NULL );
		SetThreadPriority( hashing_thread, THREAD_PRIORITY_HIGHEST );

		do
		{
			SetConsoleMode( gh_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT );
			ReadConsoleW( gh_hInput, gh_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, &crcc );

			if ( gh_console_buffer[ 0 ] == ALPHA_NUM( 'q' ) )
			{
				gh_status = 1;	// Stop

				SetEvent( gh_hashing_event );

				break;
			}
			else if ( gh_console_buffer[ 0 ] == ALPHA_NUM( 'p' ) )
			{
				if ( gh_status == 0 )
				{
					gh_status = 2;	// Pause
				}
				else if ( gh_status == 2 )
				{
					gh_status = 0;	// Resume hashing

					SetEvent( gh_hashing_event );
				}
			}
			else if ( gh_console_buffer[ 0 ] == ALPHA_NUM( 'n' ) )
			{
				gh_status = 3;	// New instance

				SetEvent( gh_hashing_event );

				break;
			}
			else if ( gh_console_buffer[ 0 ] == ALPHA_NUM( 'i' ) )
			{
				gh_show_information = !gh_show_information;	
			}
		}
		while ( read > 0 );

		WaitForSingleObject( hashing_thread, INFINITE );
		CloseHandle( hashing_thread );

		// Show the console cursor position.
		GetConsoleCursorInfo( gh_hOutput, &cci );
		cci.bVisible = TRUE;
		SetConsoleCursorInfo( gh_hOutput, &cci );

		if ( gh_hash_value != NULL )
		{
			free( gh_hash_value );
		}
	}
	while ( gh_status == 3 );

CLEANUP:

	if ( gh_hashing_event != NULL )
	{
		CloseHandle( gh_hashing_event );
	}

    cudaThreadExit();

	// Show the console cursor position.
	GetConsoleCursorInfo( gh_hOutput, &cci );
	cci.bVisible = TRUE;
	SetConsoleCursorInfo( gh_hOutput, &cci );

    return 0;
}
