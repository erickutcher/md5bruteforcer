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

#include "abv.h"

#include <stdlib.h>
#include <string.h>

void abv_init( ABV *abv, unsigned char length, unsigned char *charset, unsigned short charset_length )
{
	if ( abv != NULL )
	{
		// We have a buffer of 64 bytes to work with for our MD5 algorithm.
		// 8 bytes will be used to store the length.
		// 1 byte will be used to store the padding.
		// That leaves us 55 bytes to store input.
		// Since we're already generating a buffer of ints that have all combinations of our character set, then we'll have 55 - 4 = 51 bytes left to use here.
		if ( length > 0 && length <= 51 )
		{
			unsigned char size = ( ( length + ( sizeof( unsigned int ) - 1 ) ) / sizeof( unsigned int ) );

			abv->charset = charset;

			abv->charset_length = charset_length;//( abv->charset != NULL ? strlen( ( const char * )abv->charset ) : 0 );

			abv->size = size;	// Size in ints that the value will take up.

			abv->length = length;

			abv->val = ( unsigned int * )malloc( sizeof( unsigned int ) * 13 );
			memset( abv->val, 0, sizeof( unsigned int ) * 13 );

			abv->cval = ( unsigned int * )malloc( sizeof( unsigned int ) * 13 );
			memset( abv->cval, 0, sizeof( unsigned int ) * 13 );

			for ( unsigned char i = 0; i < abv->size; ++i )
			{
				abv->cval[ i ] = abv->charset[ 0 ] << 24 | abv->charset[ 0 ] << 16 | abv->charset[ 0 ] << 8 | abv->charset[ 0 ];
			}

			//printf( "%lu %x %x\r\n", abv->size, abv->cval[ 0 ], abv->cval[ 1 ] );
		}
	}
}

void abv_uninit( ABV *abv )
{
	if ( abv != NULL )
	{
		if ( abv->val != NULL )
		{
			free( abv->val );
			abv->val = NULL;
		}

		if ( abv->cval != NULL )
		{
			free( abv->cval );
			abv->cval = NULL;
		}

		abv->size = 0;
		abv->length = 0;
		abv->charset_length = 0;
		abv->charset = NULL;
	}
}

void abv_increment( ABV *abv )
{
	char *val_ptr, *cval_ptr;

	if ( abv != NULL )
	{
		unsigned short base = abv->charset_length;

		if ( base-- > 1 )
		{
			for ( unsigned char i = 0; i < abv->size; ++i )
			{
				val_ptr = ( char * )( &abv->val[ i ] );
				cval_ptr = ( char * )( &abv->cval[ i ] );

				for ( char j = 0; j < 4; ++j )
				{
					if ( val_ptr[ j ] >= base )
					{
						val_ptr[ j ] = 0;
						cval_ptr[ j ] = abv->charset[ 0 ];
					}
					else
					{
						++val_ptr[ j ];
						cval_ptr[ j ] = abv->charset[ val_ptr[ j ] ];

						return;
					}
				}
			}
		}
	}
}

/*
void abv_increment( ABV *abv )
{
	if ( abv != NULL )
	{
		unsigned int tmp = 0;

		unsigned short base = abv->charset_length;

		if ( base-- > 1 )
		{
			for ( unsigned char i = 0; i < abv->size; ++i )
			{
				tmp = ( abv->val[ i ] & 0x000000FF );

				if ( tmp >= base )
				{
					abv->val[ i ] &= 0xFFFFFF00;

					abv->cval[ i ] &= 0xFFFFFF00;
					abv->cval[ i ] |= abv->charset[ 0 ];

					tmp = ( ( abv->val[ i ] & 0x0000FF00 ) >> 8 );

					if ( tmp >= base )
					{
						abv->val[ i ] &= 0xFFFF00FF;

						abv->cval[ i ] &= 0xFFFF00FF;
						abv->cval[ i ] |= ( abv->charset[ 0 ] << 8 );

						tmp = ( ( abv->val[ i ] & 0x00FF0000 ) >> 16 );

						if ( tmp >= base )
						{
							abv->val[ i ] &= 0xFF00FFFF;

							abv->cval[ i ] &= 0xFF00FFFF;
							abv->cval[ i ] |= ( abv->charset[ 0 ] << 16 );

							tmp = ( ( abv->val[ i ] & 0xFF000000 ) >> 24 );

							if ( tmp >= base )
							{
								abv->val[ i ] = 0;
									
								abv->cval[ i ] &= 0x00FFFFFF;
								abv->cval[ i ] |= ( abv->charset[ 0 ] << 24 );

								continue;
							}
							else
							{
								abv->val[ i ] &= 0x00FFFFFF;
								abv->val[ i ] |= ( ( tmp + 1 ) << 24 );

								abv->cval[ i ] &= 0x00FFFFFF;
								abv->cval[ i ] |= ( abv->charset[ ( tmp + 1 ) ] << 24 );
							}
						}
						else
						{
							abv->val[ i ] &= 0xFF00FFFF;
							abv->val[ i ] |= ( ( tmp + 1 ) << 16 );

							abv->cval[ i ] &= 0xFF00FFFF;
							abv->cval[ i ] |= ( abv->charset[ ( tmp + 1 ) ] << 16 );
						}
					}
					else
					{
						abv->val[ i ] &= 0xFFFF00FF;
						abv->val[ i ] |= ( ( tmp + 1 ) << 8 );

						abv->cval[ i ] &= 0xFFFF00FF;
						abv->cval[ i ] |= ( abv->charset[ ( tmp + 1 ) ] << 8 );
					}
				}
				else
				{
					++abv->val[ i ];

					abv->cval[ i ] &= 0xFFFFFF00;
					abv->cval[ i ] |= abv->charset[ ( tmp + 1 ) ];
				}

				break;
			}
		}
	}
}
*/

void AdjustBitmask( ABV *abv )
{
	if ( abv != NULL )
	{
		unsigned char byte_offset = abv->length % sizeof( unsigned int );
		unsigned char int_offset = abv->size - 1;

		if ( byte_offset == 0 )
		{
			abv->cval[ int_offset ] = ( abv->cval[ int_offset ] & 0x0000FFFF ) | ( abv->val[ int_offset ] & 0xFFFF0000 );
		}
		else if ( byte_offset == 1 )
		{
			abv->cval[ int_offset ] = ( abv->val[ int_offset ] & 0x000000FF ) ;

			if ( int_offset > 0 )
			{
				abv->cval[ int_offset - 1 ] = ( abv->cval[ int_offset - 1 ] & 0x00FFFFFF ) | ( abv->val[ int_offset - 1 ] & 0xFF000000 ) ;
			}
		}
		else if ( byte_offset == 2 )
		{
			abv->cval[ int_offset ] = ( abv->val[ int_offset ] & 0x0000FFFF );
		}
		else if ( byte_offset == 3 )
		{
			abv->cval[ int_offset ] = ( abv->cval[ int_offset ] & 0x000000FF ) | ( abv->val[ int_offset ] & 0x00FFFFFF );
		}
	}
}

void AppendPadding( ABV *abv )
{
	if ( abv != NULL )
	{
		unsigned char byte_offset = abv->length % sizeof( unsigned int );
		unsigned char int_offset = abv->size - 1;

		if ( byte_offset )
		{
			abv->cval[ int_offset ] &= ( 0xFFFFFFFF >> ( ( sizeof( unsigned int ) - byte_offset ) << 3 ) );

			abv->cval[ int_offset ] |= ( 0x00000080 << ( byte_offset << 3 ) );
		}
		/*else
		{
			abv->cval[ int_offset ] = 0x80;
		}*/

		//printf( "%lu %x %x\r\n", abv->size, abv->cval[ 0 ], abv->cval[ 1 ] );
	}
}
