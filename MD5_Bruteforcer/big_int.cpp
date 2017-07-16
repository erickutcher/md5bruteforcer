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

#include "big_int.h"
#include "big_int_asm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void big_int_init( BIG_INT *bi )
{
	if ( bi != NULL )
	{
		bi->val_size = BUFFER_SIZE;
		bi->val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi->val_size );
		bi->val_length = 0;
	}
}

void big_int_init( BIG_INT *bi, unsigned long val )
{
	if ( bi != NULL )
	{
		bi->val_size = BUFFER_SIZE;
		bi->val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi->val_size );
		bi->val_length = 1;

		bi->val[ 0 ] = val;
	}
}

void big_int_init( BIG_INT *bi, unsigned long long val )
{
	if ( bi != NULL )
	{
		bi->val_size = BUFFER_SIZE;
		bi->val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi->val_size );

		bi->val[ 0 ] = ( unsigned long )val;
		bi->val[ 1 ] = ( unsigned long )( val >> 32 );
		if ( !bi->val[ 1 ] )
		{
			bi->val_length = 1;
		}
		else
		{
			bi->val_length = 2;
		}
	}
}

void big_int_init( BIG_INT *bi1, BIG_INT *bi2 )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		bi1->val_length = bi2->val_length;
		bi1->val_size = bi2->val_size;

		bi1->val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi1->val_size );
		memcpy_s( bi1->val, sizeof( unsigned long ) * bi1->val_size, bi2->val, bi2->val_length );
	}
}

void big_int_uninit( BIG_INT *bi )
{
	if ( bi != NULL )
	{
		if ( bi->val != NULL )
		{
			free( bi->val );
		}

		bi->val_size = 0;
	}
}

int big_int_cmp( BIG_INT *bi, unsigned long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		if ( offset < bi->val_length )
		{
			if ( bi->val[ offset ] == val )
			{
				return 0;
			}
			else if ( bi->val[ offset ] > val )
			{
				return 1;
			}
		}
	}
		
	return -1;
}

int big_int_cmp( BIG_INT *bi, unsigned long long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		if ( offset < bi->val_length )
		{
			unsigned long hi_val = val >> 32;
			unsigned long lo_val = ( unsigned long )val;

			if ( offset < bi->val_length - 1 )
			{
				if ( bi->val[ offset + 1 ] == hi_val && bi->val[ offset ] == lo_val )
				{
					return 0;
				}
				else if ( bi->val[ offset + 1 ] > hi_val )
				{
					return 1;
				}
				else if ( bi->val[ offset ] > lo_val )
				{
					return 1;
				}
			}
			else if ( hi_val > 0 )
			{
				return 1;
			}
			else
			{
				if ( bi->val[ offset ] == lo_val )
				{
					return 0;
				}
				else if ( bi->val[ offset ] > lo_val )
				{
					return 1;
				}
			}
		}
	}
		
	return -1;
}

int big_int_cmp( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset1, unsigned long offset2 )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		if ( offset1 < bi1->val_length && offset2 < bi2->val_length )
		{
			if ( ( bi1->val_length - offset1 ) == ( bi2->val_length - offset2 ) )
			{
				if ( bi1->val_length > bi2->val_length )
				{
					for ( unsigned int i = bi1->val_length; i > offset1; )
					{
						--i;

						if ( bi1->val[ i ] != bi2->val[ i - offset1 ] )
						{
							return ( ( bi1->val[ i ] > bi2->val[ i - offset1 ] ) ? 1 : -1 );
						}
					}
				}
				else if ( bi1->val_length < bi2->val_length )
				{
					for ( unsigned int i = bi2->val_length; i > offset2; )
					{
						--i;

						if ( bi1->val[ i - offset2 ] != bi2->val[ i ] )
						{
							return ( ( bi1->val[ i - offset2 ] > bi2->val[ i ] ) ? 1 : -1 );
						}
					}
				}
				else
				{
					for ( unsigned int i = bi1->val_length; i > offset1; )
					{
						--i;

						if ( bi1->val[ i ] != bi2->val[ i ] )
						{
							return ( ( bi1->val[ i ] > bi2->val[ i ] ) ? 1 : -1 );
						}
					}
				}
			}
			else
			{
				return ( ( ( bi1->val_length - offset1 ) > ( bi2->val_length - offset2 ) ) ? 1 : -1 );
			}
		}
		else if ( offset1 < bi1->val_length )
		{
			return 1;
		}
		else if ( offset2 < bi2->val_length )
		{
			return -1;
		}
	}
	else if ( bi1 != NULL )
	{
		return 1;
	}
	else if ( bi2 != NULL )
	{
		return -1;
	}

	return 0;
}

void big_int_set( BIG_INT *bi, unsigned long val )
{
	if ( bi != NULL )
	{
		bi->val[ 0 ] = val;
		bi->val_length = 1;
	}
}

void big_int_set( BIG_INT *bi, unsigned long long val )
{
	if ( bi != NULL )
	{
		bi->val[ 0 ] = ( unsigned long )val;
		bi->val[ 1 ] = ( unsigned long )( val >> 32 );
		if ( !bi->val[ 1 ] )
		{
			bi->val_length = 1;
		}
		else
		{
			bi->val_length = 2;
		}
	}
}

void big_int_set( BIG_INT *bi1, BIG_INT *bi2 )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		bi1->val_length = bi2->val_length;
		bi1->val_size = bi2->val_length;	// Match the length instead of the size.

		bi1->val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi1->val_size );
		memcpy_s( bi1->val, sizeof( unsigned long ) * bi1->val_size, bi2->val, bi2->val_length );
	}
}

void big_int_shift_left( BIG_INT *bi, unsigned long val )
{
	if ( bi != NULL )
	{
		unsigned char shift;
		unsigned long carry;
		unsigned long long tmp;

		while ( val )
		{
			if ( val > 32 )
			{
				shift = 32;
			}
			else
			{
				shift = ( unsigned char )val;
			}

			for ( unsigned long i = bi->val_length; i > 0; )
			{
				--i;

				tmp = ( unsigned long long )bi->val[ i ] << shift;

				// Update the size/length if the last value needs to be carried.
				if ( i == ( bi->val_length - 1 ) )
				{
					carry = ( tmp >> 32 );

					if ( carry )
					{
						if ( bi->val_length >= bi->val_size )
						{
							unsigned long *new_val = ( unsigned long * )realloc( bi->val, sizeof( unsigned long ) * ( bi->val_size + BUFFER_SIZE ) );

							if ( new_val != NULL )
							{
								bi->val = new_val;
								bi->val_size += BUFFER_SIZE;
							}
							else
							{
								return;
							}
						}

						bi->val[ bi->val_length++ ] = carry;
					}
				}

				bi->val[ i ] = ( unsigned long )tmp;

				if ( i > 0 )
				{
					bi->val[ i ] |= ( bi->val[ i - 1 ] >> ( 32 - shift ) );
				}
			}

			val -= shift;
		}
	}
}

void big_int_shift_right( BIG_INT *bi, unsigned long val )
{
	if ( bi != NULL )
	{
		unsigned char shift;
		unsigned long long tmp;
		bool dec_length;

		while ( val )
		{
			if ( val > 32 )
			{
				shift = 32;
			}
			else
			{
				shift = ( unsigned char )val;
			}

			for ( unsigned long i = 0; i < bi->val_length; ++i )
			{
				tmp = ( unsigned long long )bi->val[ i ] >> shift;

				// Update the size/length if the last value needs to be carried.
				if ( i == ( bi->val_length - 1 ) )
				{
					dec_length = false;

					if ( tmp == 0 )
					{
						dec_length = true;
					}
				}

				bi->val[ i ] = ( unsigned long )tmp;

				if ( i < bi->val_length - 1 )
				{
					bi->val[ i ] |= ( bi->val[ i + 1 ] << ( 32 - shift ) );
				}
			}

			if ( dec_length )
			{
				--bi->val_length;
			}

			val -= shift;
		}
	}
}

void big_int_add( BIG_INT *bi, unsigned long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		unsigned long long carry = val;

		for ( unsigned long i = offset; i < bi->val_length; ++i )
		{
			carry += bi->val[ i ];

			bi->val[ i ] = ( unsigned long )carry;
			carry >>= 32;

			if ( !carry )
			{
				break;
			}
		}

		if ( carry )
		{
			if ( bi->val_length >= bi->val_size )
			{
				unsigned long *new_val = ( unsigned long * )realloc( bi->val, sizeof( unsigned long ) * ( bi->val_size + BUFFER_SIZE ) );

				if ( new_val != NULL )
				{
					bi->val = new_val;
					bi->val_size += BUFFER_SIZE;
				}
				else
				{
					return;
				}
			}

			bi->val[ bi->val_length++ ] = ( unsigned long )carry;
		}
	}
}


void big_int_add( BIG_INT *bi, unsigned long long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		unsigned long long carry = val >> 32;

		val &= 0x00000000FFFFFFFF;

		for ( char i = 1; i >= 0; --i )
		{
			for ( unsigned long long j = ( i + offset ); j < bi->val_length; ++j )
			{
				carry += bi->val[ j ];

				bi->val[ j ] = ( unsigned long )carry;
				carry >>= 32;

				if ( !carry )
				{
					break;
				}
			}

			if ( carry )
			{
				if ( bi->val_length >= bi->val_size )
				{
					unsigned long *new_val = ( unsigned long * )realloc( bi->val, sizeof( unsigned long ) * ( bi->val_size + BUFFER_SIZE ) );

					if ( new_val != NULL )
					{
						bi->val = new_val;
						bi->val_size += BUFFER_SIZE;
					}
					else
					{
						return;
					}
				}

				bi->val[ bi->val_length++ ] = ( unsigned long )carry;
			}

			carry = val;
		}
	}
}

void big_int_add( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		unsigned long long carry;

		// Resize the first big int to the size of the second if it's smaller than the second.
		if ( bi1->val_size < bi2->val_size )
		{
			unsigned long *new_val = ( unsigned long * )realloc( bi1->val, sizeof( unsigned long ) * bi2->val_size );

			if ( new_val != NULL )
			{
				bi1->val = new_val;
				bi1->val_size = bi2->val_size;
			}
			else
			{
				return;
			}
		}

		// Zero out any extra ints if we have to adjust the size.
		if ( bi1->val_length < bi2->val_length )
		{
			memset( bi1->val + bi1->val_length, 0, sizeof( unsigned long ) * ( bi1->val_size - bi1->val_length ) );
			bi1->val_length = bi2->val_length;
		}

		for ( unsigned long i = bi2->val_length; i > 0; )
		{
			--i;

			carry = bi2->val[ i ];

			for ( unsigned long long j = ( i + offset ); j < bi1->val_length; ++j )
			{
				carry += bi1->val[ j ];

				bi1->val[ j ] = ( unsigned long )carry;
				carry >>= 32;

				if ( !carry )
				{
					break;
				}
			}

			if ( carry )
			{
				if ( bi1->val_length >= bi1->val_size )
				{
					unsigned long *new_val = ( unsigned long * )realloc( bi1->val, sizeof( unsigned long ) * ( bi1->val_size + BUFFER_SIZE ) );

					if ( new_val != NULL )
					{
						bi1->val = new_val;
						bi1->val_size += BUFFER_SIZE;
					}
					else
					{
						return;
					}
				}

				bi1->val[ bi1->val_length++ ] = ( unsigned long )carry;
			}
		}
	}
}

void big_int_sub( BIG_INT *bi, unsigned long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		unsigned long long borrow = val;

		for ( unsigned long i = offset; i < bi->val_length; ++i )
		{
			borrow = bi->val[ i ] - borrow;

			bi->val[ i ] = ( unsigned long )borrow;
			borrow >>= 32;

			if ( 0x00000000FFFFFFFF == borrow )
			{
				borrow = 1;
			}
			else if ( !borrow )
			{
				break;
			}
		}

		// Must iterate back if our offset was greater than 0.
		while ( bi->val_length > 1 && bi->val[ bi->val_length - 1 ] == 0 )
		{
			--bi->val_length;
		}
	}
}

void big_int_sub( BIG_INT *bi, unsigned long long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		unsigned long long borrow = val >> 32;

		val &= 0x00000000FFFFFFFF;

		for ( char i = 1; i >= 0; --i )
		{
			for ( unsigned long long j = ( i + offset ); j < bi->val_length; ++j )
			{
				borrow = bi->val[ j ] - borrow;

				bi->val[ j ] = ( unsigned long )borrow;
				borrow >>= 32;

				if ( 0x00000000FFFFFFFF == borrow )
				{
					borrow = 1;
				}
				else if ( !borrow )
				{
					break;
				}
			}

			if ( bi->val_length > 1 && bi->val[ bi->val_length - 1 ] == 0 )
			{
				--bi->val_length;
			}

			borrow = val;
		}
	}
}
void big_int_sub( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		unsigned long long borrow;

		for ( unsigned long i = bi2->val_length; i > 0; )
		{
			--i;

			borrow = bi2->val[ i ];

			for ( unsigned long j = ( i + offset ); j < bi1->val_length; ++j )
			{
				borrow = bi1->val[ j ] - borrow;

				bi1->val[ j ] = ( unsigned long )borrow;
				borrow >>= 32;

				if ( 0x00000000FFFFFFFF == borrow )
				{
					borrow = 1;
				}
				else if ( !borrow )
				{
					break;
				}
			}

			if ( bi1->val_length > 1 && bi1->val[ bi1->val_length - 1 ] == 0 )
			{
				--bi1->val_length;
			}
		}
	}
}

void big_int_mul( BIG_INT *bi, unsigned long val )
{
	if ( bi != NULL )
	{
		unsigned long long carry = 0;

		for ( unsigned long i = 0; i < bi->val_length; ++i )
		{
			carry += val * ( unsigned long long )bi->val[ i ];
			bi->val[ i ] = ( unsigned long )carry;
			carry >>= 32;
		}

		if ( carry )
		{
			if ( bi->val_length >= bi->val_size )
			{
				unsigned long *new_val = ( unsigned long * )realloc( bi->val, sizeof( unsigned long ) * ( bi->val_size + BUFFER_SIZE ) );

				if ( new_val != NULL )
				{
					bi->val = new_val;
					bi->val_size += BUFFER_SIZE;
				}
				else
				{
					return;
				}
			}

			bi->val[ bi->val_length++ ] = ( unsigned long )carry;
		}
	}
}

void big_int_mul( BIG_INT *bi, unsigned long long val )
{
	if ( bi != NULL )
	{
		BIG_INT bi_copy;

		unsigned long long carry;

		bi_copy.val_size = bi->val_length + 2;
		bi_copy.val_length = bi->val_length;

		bi_copy.val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi_copy.val_size );
		memset( bi_copy.val, 0, sizeof( unsigned long ) * bi_copy.val_size );

		unsigned long *val_ptr = bi_copy.val;

		for ( unsigned char i = 0; i < 2; ++i )
		{
			carry = 0;

			for ( unsigned long j = 0; j < bi->val_length; ++j )
			{
				carry += val_ptr[ j ] + ( ( unsigned long )val * ( unsigned long long )bi->val[ j ] );
				val_ptr[ j ] = ( unsigned long )carry;
				carry >>= 32;
			}

			val_ptr[ bi_copy.val_length ] = ( unsigned long )carry;

			++val_ptr;

			val >>= 32;
		}

		// Figure out the length of our new value.
		for ( unsigned long i = bi_copy.val_size; i > bi_copy.val_length; )
		{
			--i;

			if ( bi_copy.val[ i ] != 0 )
			{
				bi_copy.val_length = i + 1;

				break;
			}
		}

		val_ptr = bi->val;
		*bi = bi_copy;
		bi_copy.val = val_ptr;

		big_int_uninit( &bi_copy );
	}
}


void big_int_mul( BIG_INT *bi1, BIG_INT *bi2 )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		BIG_INT bi_copy;

		unsigned long long carry;
		unsigned long val;

		bi_copy.val_size = bi1->val_length + bi2->val_length;
		bi_copy.val_length = bi1->val_length;

		bi_copy.val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi_copy.val_size );
		memset( bi_copy.val, 0, sizeof( unsigned long ) * bi_copy.val_size );

		unsigned long *val_ptr = bi_copy.val;

		for ( unsigned long i = 0; i < bi2->val_length; ++i )
		{
			carry = 0;
			val = bi2->val[ i ];

			for ( unsigned long j = 0; j < bi1->val_length; ++j )
			{
				carry += val_ptr[ j ] + ( val * ( unsigned long long )bi1->val[ j ] );
				val_ptr[ j ] = ( unsigned long )carry;
				carry >>= 32;
			}

			val_ptr[ bi_copy.val_length ] = ( unsigned long )carry;

			++val_ptr;
		}

		// Figure out the length of our new value.
		for ( unsigned long i = bi_copy.val_size; i > bi_copy.val_length; )
		{
			--i;

			if ( bi_copy.val[ i ] != 0 )
			{
				bi_copy.val_length = i + 1;

				break;
			}
		}

		val_ptr = bi1->val;
		*bi1 = bi_copy;
		bi_copy.val = val_ptr;

		big_int_uninit( &bi_copy );
	}
}

void big_int_div( BIG_INT *bi, unsigned long val )
{
	if ( bi != NULL && bi->val_length > 0 && val > 0 )
	{
		unsigned long long carry = 0;

		for ( unsigned long i = bi->val_length; i > 0; )
		{
			--i;

			carry |= bi->val[ i ];

			bi->val[ i ] = ( unsigned long )( carry / val );
			carry = ( ( unsigned long long )( carry % val ) ) << 32;
		}

		if ( bi->val[ bi->val_length - 1 ] == 0 )
		{
			--bi->val_length;
		}
	}
}

void big_int_div( BIG_INT *bi1, BIG_INT *bi2 )
{
	if ( bi1 != NULL && bi2 != NULL && bi1->val_length > 0 && bi2->val_length > 0 && ( bi1->val_length >= bi2->val_length ) )
	{
		// Handle a divisor of 0 and all 32 bit divisors.
		if ( bi2->val_length == 1 )
		{
			big_int_div_asm( bi1, bi2->val[ 0 ] );

			return;
		}

		BIG_INT bi_dividend;
		bi_dividend.val_length = bi1->val_length;
		bi_dividend.val_size = bi1->val_length + 1;
		bi_dividend.val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi_dividend.val_size );
		memcpy_s( bi_dividend.val, sizeof( unsigned long ) * bi_dividend.val_size, bi1->val, sizeof( unsigned long ) * bi1->val_length );

		BIG_INT bi_divisor;
		bi_divisor.val_length = bi2->val_length;
		bi_divisor.val_size = bi2->val_length;
		bi_divisor.val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi_divisor.val_size );
		memcpy_s( bi_divisor.val, sizeof( unsigned long ) * bi_divisor.val_size, bi2->val, sizeof( unsigned long ) * bi2->val_length );

		unsigned long scale = ( unsigned long )( 0x0000000100000000 / ( bi_divisor.val[ bi_divisor.val_length - 1 ] + 1 ) );

		if ( scale != 1 )
		{
			big_int_mul( &bi_dividend, scale );
			big_int_mul( &bi_divisor, scale );
		}

		unsigned long divisor = bi_divisor.val[ bi_divisor.val_length - 1 ];

		if ( bi_dividend.val[ bi_dividend.val_length - 1 ] >= divisor )
		{
			bi_dividend.val[ bi_dividend.val_length++ ] = 0;
		}

		bi1->val_length = bi_dividend.val_length - bi2->val_length;

		do
		{
			unsigned long multiplier = ( unsigned long )( *( unsigned long long * )&bi_dividend.val[ bi_dividend.val_length - 2 ] / divisor );

			BIG_INT bi_dividend_ptr;
			bi_dividend_ptr.val = &bi_dividend.val[ bi_dividend.val_length - 3 ];
			bi_dividend_ptr.val_length = 3;

			if ( multiplier > 0 )
			{
				unsigned long long carry1 = 0;
				unsigned long long carry2 = 1;

				for ( unsigned long i = 0; i < bi_divisor.val_length; ++i )
				{
					carry1 += multiplier * ( unsigned long long )bi_divisor.val[ i ];
					carry2 += bi_dividend_ptr.val[ i ];
					carry2 += 0xFFFFFFFF;
					carry2 -= ( unsigned long )carry1;
					bi_dividend_ptr.val[ i ] = ( unsigned long )carry2;
					carry1 >>= 32;
					carry2 >>= 32;
				}

				carry2 += bi_dividend_ptr.val[ bi_divisor.val_length ];
				carry2 += 0xFFFFFFFF;
				carry2 -= carry1;

				if ( ( unsigned long )carry2 == 0 )
				{
					bi_dividend_ptr.val[ bi_divisor.val_length ] = ( unsigned long )carry2;

					--bi_dividend_ptr.val_length;
				}
				else
				{
					big_int_add( &bi_dividend_ptr, &bi_divisor );

					--multiplier;
				}
			}

			--bi_dividend.val_length;

			bi1->val[ bi_dividend.val_length - 2 ] = multiplier;

		}
		while ( bi_dividend.val_length > 2 );

		big_int_uninit( &bi_dividend );
		big_int_uninit( &bi_divisor );
	}
}

void big_int_pow( BIG_INT *bi, unsigned long val )
{
	if ( bi != NULL )
	{
		if ( !val )
		{
			bi->val[ 0 ] = 1;
			bi->val_length = 1;
		}
		else
		{
			BIG_INT bi_copy;
			BIG_INT bi_pow;

			unsigned long *val_ptr;

			bi_copy.val_size = bi->val_length;
			bi_copy.val_length = bi->val_length;

			bi_copy.val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi_copy.val_size );
			memcpy_s( bi_copy.val, sizeof( unsigned long ) * bi_copy.val_size, bi->val, sizeof( unsigned long ) * bi->val_length );

			big_int_init( &bi_pow );
			big_int_set( &bi_pow, ( unsigned long )1 );

			while ( true )
			{
				// If val is odd
				if ( val & 1 )
				{
					big_int_mul( &bi_pow, &bi_copy );
				}

				val >>= 1;

				if ( !val )
				{
					break;
				}

				big_int_mul( &bi_copy, &bi_copy );
			}

			val_ptr = bi->val;
			*bi = bi_pow;
			bi_pow.val = val_ptr;
			
			big_int_uninit( &bi_copy );
			big_int_uninit( &bi_pow );
		}
	}
}

void big_int_print( BIG_INT *bi )
{
	if ( bi != NULL && bi->val_length > 0 )
	{
		unsigned long long *val = ( unsigned long long * )malloc( sizeof( unsigned long long ) * ( bi->val_length ) );

		long *result = ( long * )malloc( sizeof( long ) * ( bi->val_length * 2 ) );

		bool finished = false;
		long long count = 0;
		unsigned long long carry;

		for ( unsigned long i = 0; i < bi->val_length; ++i )
		{
			val[ i ] = bi->val[ i ];
		}

		while ( !finished )
		{
			finished = true;

			carry = 0;

			for ( unsigned long i = bi->val_length; i > 0; )
			{
				--i;

				carry = ( carry << 32 ) + val[ i ];

				val[ i ] = carry / 100000000;
				carry -= val[ i ] * 100000000;

				if ( val[ i ] )
				{
					finished = false;
				}
			}

			result[ count++ ] = ( long )carry;
		}

		printf( "%d", result[ --count ] );

		/*while ( count > 0 )
		{
			printf( "%08lu", result[ --count ] );
		}*/

		/*unsigned char loop_count = count % 16;
		while ( count > loop_count )
		{
			printf( "%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu",
					result[ count - 1 ],
					result[ count - 2 ],
					result[ count - 3 ],
					result[ count - 4 ],
					result[ count - 5 ],
					result[ count - 6 ],
					result[ count - 7 ],
					result[ count - 8 ] );

			count -= 8;
		}*/

		unsigned char loop_count = count % 16;
		while ( count > loop_count )
		{
			printf( "%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu%08lu",
					result[ count - 1 ],
					result[ count - 2 ],
					result[ count - 3 ],
					result[ count - 4 ],
					result[ count - 5 ],
					result[ count - 6 ],
					result[ count - 7 ],
					result[ count - 8 ],
					result[ count - 9 ],
					result[ count - 10 ],
					result[ count - 11 ],
					result[ count - 12 ],
					result[ count - 13 ],
					result[ count - 14 ],
					result[ count - 15 ],
					result[ count - 16 ] );

			count -= 16;
		}

		while ( count > 0 )
		{
			printf( "%08lu", result[ --count ] );
		}

		free( val );
		free( result );
	}
}

double big_int_simple_percent( BIG_INT *bi1, BIG_INT *bi2 )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		unsigned long long a = 0;
		unsigned long long b = 0;

		if ( bi1->val_length == bi2->val_length )
		{
			//a = ( bi1->val_length > 1 ? ( ( ( unsigned long long )bi1->val[ bi1->val_length - 1 ] << 32 ) | bi1->val[ bi1->val_length - 2 ] ) : bi1->val[ 0 ] );
			a = ( bi1->val_length > 1 ? *( unsigned long long * )( bi1->val + ( bi1->val_length - 2 ) ) : bi1->val[ 0 ] );
			//b = ( bi2->val_length > 1 ? ( ( ( unsigned long long )bi2->val[ bi2->val_length - 1 ] << 32 ) | bi2->val[ bi2->val_length - 2 ] ) : bi2->val[ 0 ] );
			b = ( bi2->val_length > 1 ? *( unsigned long long * )( bi2->val + ( bi2->val_length - 2  ) ) : bi2->val[ 0 ] );
		}
		else if ( bi1->val_length == bi2->val_length + 1 )
		{
			//a = ( bi1->val_length > 1 ? ( ( ( unsigned long long )bi1->val[ bi1->val_length - 1 ] << 32 ) | bi1->val[ bi1->val_length - 2 ] ) : bi1->val[ 0 ] );
			a = ( bi1->val_length > 1 ? *( unsigned long long * )( bi1->val + ( bi1->val_length - 2 ) ) : bi1->val[ 0 ] );
			b = bi2->val[ bi2->val_length - 1 ];
		}
		else if ( bi2->val_length == bi1->val_length + 1 )
		{
			a = bi1->val[ bi1->val_length - 1 ];
			//b = ( bi2->val_length > 1 ? ( ( ( unsigned long long )bi2->val[ bi2->val_length - 1 ] << 32 ) | bi2->val[ bi2->val_length - 2 ] ) : bi2->val[ 0 ] );
			b = ( bi2->val_length > 1 ? *( unsigned long long * )( bi2->val + ( bi2->val_length - 2  ) ) : bi2->val[ 0 ] );
		}
		else if ( bi1->val_length >= bi2->val_length + 2 )
		{
			return 0.0f;
		}
		else if ( bi2->val_length >= bi1->val_length + 2 )
		{
			return 1.0f;
		}

		if ( a )
		{
			return ( double )b / ( double )a;
		}
	}

	return 0.0f;
}
