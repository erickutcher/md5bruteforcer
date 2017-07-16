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

#ifndef _MD5_CUH
#define _MD5_CUH

#define S11		7
#define S12		12
#define S13		17
#define S14		22
#define S21		5
#define S22		9
#define S23		14
#define S24		20
#define S31		4
#define S32		11
#define S33		16
#define S34		23
#define S41		6
#define S42		10
#define S43		15
#define S44		21

#define F( x, y, z ) ( ( ( ( y ) ^ ( z ) ) & ( x ) ) ^ ( z ) )
#define G( x, y, z ) ( ( ( ( x ) ^ ( y ) ) & ( z ) ) ^ ( y ) )
#define H( x, y, z ) ( ( x ) ^ ( y ) ^ ( z ) )
#define I( x, y, z ) ( ( y ) ^ ( ( x ) | ( ~z ) ) )
#define Ht( x, z ) ( ( x ) ^ ( z ) )

#define ROTATE_LEFT( x, n ) ( ( ( x ) << ( n ) ) | ( ( x ) >> ( 32 - ( n ) ) ) )
#define ROTATE_RIGHT( x, n ) ( ( ( x ) >> ( n ) ) | ( ( x ) << ( 32 - ( n ) ) ) )

// REVERSAL

#define RII( a, b, c, d, x, s, ac ) \
{ \
	( a ) -= ( b ); \
	( a ) = ROTATE_RIGHT( ( a ), ( s )); \
	( a ) -= I( ( b ), ( c ), ( d ) ) + ( x ) + ( ac ); \
}

#define RII0( a, b, c, d, s, ac ) \
{ \
	( a ) -= ( b ); \
	( a ) = ROTATE_RIGHT( ( a ), ( s ) ); \
	( a ) -= I( ( b ), ( c ), ( d ) ) + ( ac ); \
}

#define RHH( a, b, c, d, x, s, ac ) \
{ \
	( a ) -= ( b ); \
	( a ) = ROTATE_RIGHT( ( a ), ( s ) ); \
	( a ) -= ( x ) + ( ac ); \
}

#define RHH0( a, b, c, d, s, ac ) \
{ \
	( a ) -= ( b ); \
	( a ) = ROTATE_RIGHT( ( a ), ( s ) ); \
	( a ) -= ( ac ); \
}

// FORWARD

#define FF( a, b, c, d, x, s, ac ) \
{ \
	( a ) += F( ( b ), ( c ), ( d ) ) + ( x ) + ( ac ); \
	( a ) = ROTATE_LEFT( ( a ), ( s ) ); \
	( a ) += ( b ); \
}

#define FF0( a, b, c, d, s, ac ) \
{ \
	( a ) += F( ( b ), ( c ), ( d ) ) + ( ac ); \
	( a ) = ROTATE_LEFT( ( a ), ( s ) ); \
	( a ) += ( b ); \
}

//

#define GG( a, b, c, d, x, s, ac ) \
{ \
	( a ) += G( ( b ), ( c ), ( d ) ) + ( x ) + ( ac ); \
	( a ) = ROTATE_LEFT( ( a ), ( s ) ); \
	( a ) += ( b ); \
}

#define GG0(a, b, c, d, s, ac ) \
{ \
	( a ) += G( ( b ), ( c ), ( d ) ) + ( ac ); \
	( a ) = ROTATE_LEFT( ( a ), ( s ) ); \
	( a ) += ( b ); \
}

//

#define HHa( a, b, c, d, x, s, ac, t ) \
{ \
	( a ) += Ht( ( t ), ( d ) ) + ( x ) + ( ac ); \
	( a ) = ROTATE_LEFT( ( a ), ( s ) ); \
	( a ) += ( b ); \
}

#define HHa0( a, b, c, d, s, ac, t ) \
{ \
	( a ) += Ht( ( t ), ( d ) ) + ( ac ); \
	( a ) = ROTATE_LEFT( ( a ), ( s ) ); \
	( a ) += ( b ); \
}

#define HHb( a, b, c, d, x, s, ac, t ) \
{ \
	( a ) += Ht( ( b ), ( t ) ) + ( x ) + ( ac ); \
	( a ) = ROTATE_LEFT( ( a ), ( s ) ); \
	( a ) += ( b ); \
}

#define HHb0( a, b, c, d, s, ac, t ) \
{ \
	( a ) += Ht( ( b ), ( t ) ) + ( ac ); \
	( a ) = ROTATE_LEFT( ( a ), ( s ) ); \
	( a ) += ( b ); \
}

//

__device__ unsigned int *gd_input_chunk;
__device__ unsigned int *gd_input_chunk2;

__device__ unsigned int *gd_reversed_hash_values;

__device__ unsigned int gd_found_hash_input[ 14 ];
__device__ unsigned char *gd_character_set;
__device__ unsigned short gd_character_set_size;

__device__ unsigned int gd_hash_value[ 4 ];

__device__ bool	gd_hash_found;

#endif
