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

#include "big_int_asm.h"

#include <stdlib.h>
#include <string.h>

void big_int_add_asm( BIG_INT *bi, unsigned long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		unsigned long carry = val;
		unsigned long *val_ptr = bi->val + offset;

		for ( unsigned long i = offset; i < bi->val_length; ++i )
		{
			__asm
			{
				mov		eax, dword ptr [ carry ]	;// Load the value to add
				mov		esi, dword ptr [ val_ptr ]	;// Load the offset int array
				add		dword ptr [ esi ], eax		;// Add int to our big int
				jc		add_carry					;// Don't add carry value if not set
				mov		dword ptr [ carry ], 0		;// Set carry value
				jmp		end_add						;// Exit the loop
			add_carry:
				mov		dword ptr [ carry ], 1		;// Set carry value to add
			}

			++val_ptr;
		}

		/*unsigned long val_length = bi->val_length;
		unsigned long t_offset = offset;

		__asm
		{
			mov		ebx, dword ptr [ carry ]			;
			mov		ecx, dword ptr [ t_offset ]			;
			mov		edx, dword ptr [ val_length	]		;
			mov		esi, dword ptr [ val_ptr ]			;// Load the offset int array
		L01:
			mov		eax, ebx							;// Load the value to add
			add		dword ptr [ esi + 4 * ecx ], eax	;// Add int to our big int
			jc		add_carry							;// Don't add carry value if not set
			mov		dword ptr [ carry ], 0				;// Set carry value to 0
			jmp		end_add								;// Exit the loop
		add_carry:
			mov		ebx, 1								;// Set carry value to add
			inc		ecx									;
			cmp		ecx, edx							;
			jb		L01									;
			mov		dword ptr [ carry ], 1				;// Set carry value to add
		}*/

end_add:

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
}

void big_int_add_asm( BIG_INT *bi, unsigned long long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		unsigned long carry = val >> 32;
		unsigned long *val_ptr;

		val &= 0x00000000FFFFFFFF;

		for ( char i = 1; i >= 0; --i )
		{
			val_ptr = bi->val + ( i + offset );

			for ( unsigned long long j = ( i + offset ); j < bi->val_length; ++j )
			{
				__asm
				{
					mov		eax, dword ptr [ carry ]	;// Load the value to add
					mov		esi, dword ptr [ val_ptr ]	;// Load the offset int array
					add		dword ptr [ esi ], eax		;// Add int to our big int
					jc		add_carry					;// Don't add carry value if not set
					mov		dword ptr [ carry ], 0		;// Set carry value
					jmp		end_add						;// Exit the loop
				add_carry:
					mov		dword ptr [ carry ], 1		;// Set carry value to add
				}

				++val_ptr;
			}

end_add:

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

			carry = ( unsigned long )val;
		}
	}
}

void big_int_add_asm( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		unsigned long carry;
		unsigned long *val_ptr;

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

		for ( unsigned long i = 0; i < bi2->val_length; ++i )
		{
			carry = bi2->val[ i ];

			val_ptr = bi1->val + ( i + offset );

			for ( unsigned long long j = ( i + offset ); j < bi1->val_length; ++j )
			{
				__asm
				{
					mov		eax, dword ptr [ carry ]	;// Load the value to add
					mov		esi, dword ptr [ val_ptr ]	;// Load the offset int array
					add		dword ptr [ esi ], eax		;// Add int to our big int
					jc		add_carry					;// Don't add carry value if not set
					mov		dword ptr [ carry ], 0		;// Set carry value
					jmp		end_add						;// Exit the loop
				add_carry:
					mov		dword ptr [ carry ], 1		;// Set carry value to add
				}

				++val_ptr;
			}

end_add:

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

				bi1->val[ bi1->val_length++ ] = carry;
			}
		}
	}
}

void big_int_sub_asm( BIG_INT *bi, unsigned long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		unsigned long borrow = val;
		unsigned long *val_ptr = bi->val + offset;

		for ( unsigned long i = offset; i < bi->val_length; ++i )
		{
			__asm
			{
				mov		eax, dword ptr [ borrow ]	;// Load the value to subtract
				mov		esi, dword ptr [ val_ptr ]	;// Load the offset int array
				sub		dword ptr [ esi ], eax		;// Subtract int to our big int
				jc		sub_borrow					;// Don't subtract borrow value if not set
				mov		dword ptr [ borrow ], 0		;// Set borrow value
				jmp		end_sub						;// Exit the loop
			sub_borrow:
				mov		dword ptr [ borrow ], 1		;// Set borrow value to subtract
			}

			++val_ptr;
		}

end_sub:

		// Must iterate back if our offset was greater than 0.
		while ( bi->val_length > 1 && bi->val[ bi->val_length - 1 ] == 0 )
		{
			--bi->val_length;
		}
	}
}
void big_int_sub_asm( BIG_INT *bi, unsigned long long val, unsigned long offset )
{
	if ( bi != NULL )
	{
		unsigned long borrow = val >> 32;
		unsigned long *val_ptr;

		val &= 0x00000000FFFFFFFF;

		for ( char i = 1; i >= 0; --i )
		{
			val_ptr = bi->val + ( i + offset );

			for ( unsigned long long j = ( i + offset ); j < bi->val_length; ++j )
			{
				__asm
				{
					mov		eax, dword ptr [ borrow ]	;// Load the value to subtract
					mov		esi, dword ptr [ val_ptr ]	;// Load the offset int array
					sub		dword ptr [ esi ], eax		;// Subtract int to our big int
					jc		sub_borrow					;// Don't subtract borrow value if not set
					mov		dword ptr [ borrow ], 0		;// Set borrow value
					jmp		end_sub						;// Exit the loop
				sub_borrow:
					mov		dword ptr [ borrow ], 1		;// Set borrow value to subtract
				}

				++val_ptr;
			}

end_sub:

			if ( bi->val_length > 1 && bi->val[ bi->val_length - 1 ] == 0 )
			{
				--bi->val_length;
			}

			borrow = ( unsigned long )val;
		}
	}
}

void big_int_sub_asm( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		unsigned long borrow;
		unsigned long *val_ptr;

		for ( unsigned long i = bi2->val_length; i > 0; )
		{
			--i;

			borrow = bi2->val[ i ];

			val_ptr = bi1->val + ( i + offset );

			for ( unsigned long long j = ( i + offset ); j < bi1->val_length; ++j )
			{
				__asm
				{
					mov		eax, dword ptr [ borrow ]	;// Load the value to subtract
					mov		esi, dword ptr [ val_ptr ]	;// Load the offset int array
					sub		dword ptr [ esi ], eax		;// Subtract int to our big int
					jc		sub_borrow					;// Don't subtract borrow value if not set
					mov		dword ptr [ borrow ], 0		;// Set borrow value
					jmp		end_sub						;// Exit the loop
				sub_borrow:
					mov		dword ptr [ borrow ], 1		;// Set borrow value to subtract
				}

				++val_ptr;
			}

end_sub:

			if ( bi1->val_length > 1 && bi1->val[ bi1->val_length - 1 ] == 0 )
			{
				--bi1->val_length;
			}

		}
	}
}

void big_int_mul_asm( BIG_INT *bi, unsigned long val )
{
	if ( bi != NULL )
	{
		unsigned long carry = 0;
		unsigned long *val_ptr = bi->val;

		for ( unsigned long i = 0; i < bi->val_length; ++i )
		{
			/*__asm
			{
				mov		eax, dword ptr [ val ]		;// Load the value to multiply
				mov		esi, dword ptr [ val_ptr ]	;// Load the offset int array
				mov		ebx, [ esi ]				;// Load the value to multiply
				mul		ebx							;// Multiply int by our big int
				add		eax, dword ptr [ carry ]	;
				mov		[ esi ], eax;				;// Set the multiplied value
				mov		dword ptr [ carry ], edx	;// Set carry value to multiply
				jnc		skip_inc					;// Don't multiply carry value if not set
				inc		dword ptr [ carry ]			;// Set carry value
			skip_inc:
			}*/

			__asm
			{
				mov		eax, dword ptr [ val ]		;// Load the value to multiply
				mov		ebx, dword ptr [ val_ptr ]	;// Load the value to multiply
				mul		dword ptr [ ebx ]			;// Multiply int by our big int
				add		eax, dword ptr [ carry ];	;// Add our previous carry value
				mov		dword ptr [ ebx ], eax;		;// Set the multiplied value
				mov		dword ptr [ carry ], edx	;// Set carry value to multiply
				jnc		skip_inc					;// Don't increment the carry value if not set
				inc		dword ptr [ carry ]			;// Increment the carry value
			skip_inc:
			}

			++val_ptr;
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

			bi->val[ bi->val_length++ ] = carry;
		}
	}
}

void big_int_mul_asm( BIG_INT *bi, unsigned long long val )
{
	if ( bi != NULL )
	{
		BIG_INT bi_copy;

		unsigned long carry;

		unsigned long tmp_val = ( unsigned long )val;

		bi_copy.val_size = bi->val_length + 2;
		bi_copy.val_length = bi->val_length;

		bi_copy.val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi_copy.val_size );
		memset( bi_copy.val, 0, sizeof( unsigned long ) * bi_copy.val_size );

		unsigned long *val_ptr = bi_copy.val;

		unsigned long *a_val_ptr, *b_val_ptr;

		for ( unsigned char i = 0; i < 2; ++i )
		{
			carry = 0;

			a_val_ptr = bi->val;
			b_val_ptr = val_ptr;

			for ( unsigned long j = 0; j < bi->val_length; ++j )
			{
				__asm
				{
					mov		eax, dword ptr [ tmp_val ]		;// Load the value to multiply
					mov		ebx, dword ptr [ a_val_ptr ]	;// Load the value to multiply
					mul		dword ptr [ ebx ]				;// Multiply int by our big int
					add		eax, dword ptr [ carry ];		;// Add our previous carry value
					jnc		skip_inc1						;// Don't increment the carry value if not set
					inc		edx								;// Increment the carry value
				skip_inc1:
					mov		ebx, dword ptr [ b_val_ptr ]	;
					add		eax, dword ptr [ ebx ]			;
					mov		dword ptr [ ebx ], eax;			;// Set the multiplied value
					mov		dword ptr [ carry ], edx		;// Set carry value to multiply
					jnc		skip_inc2						;// Don't increment the carry value if not set
					inc		dword ptr [ carry ]				;// Increment the carry value
				skip_inc2:
				}

				++a_val_ptr;
				++b_val_ptr;
			}

			val_ptr[ bi_copy.val_length ] = carry;

			++val_ptr;

			tmp_val = val >> 32;
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

void big_int_mul_asm( BIG_INT *bi1, BIG_INT *bi2 )
{
	if ( bi1 != NULL && bi2 != NULL )
	{
		BIG_INT bi_copy;

		unsigned long carry;

		bi_copy.val_size = bi1->val_length + bi2->val_length;
		bi_copy.val_length = bi1->val_length;

		bi_copy.val = ( unsigned long * )malloc( sizeof( unsigned long ) * bi_copy.val_size );
		memset( bi_copy.val, 0, sizeof( unsigned long ) * bi_copy.val_size );

		unsigned long *val_ptr = bi_copy.val;

		unsigned long *a_val_ptr, *b_val_ptr = bi2->val, *c_val_ptr;

		for ( unsigned long i = 0; i < bi2->val_length; ++i )
		{
			carry = 0;

			a_val_ptr = bi1->val;
			c_val_ptr = val_ptr;

			for ( unsigned long j = 0; j < bi1->val_length; ++j )
			{
				__asm
				{
					mov		ebx, dword ptr [ b_val_ptr ]	;// Load the value to multiply
					mov		eax, dword ptr [ ebx ]			;// Load the value to multiply
					mov		ebx, dword ptr [ a_val_ptr ]	;// Load the value to multiply
					mul		dword ptr [ ebx ]				;// Multiply int by our big int
					add		eax, dword ptr [ carry ];		;// Add our previous carry value
					jnc		skip_inc1						;// Don't increment the carry value if not set
					inc		edx								;// Increment the carry value
				skip_inc1:
					mov		ebx, dword ptr [ c_val_ptr ]	;
					add		eax, dword ptr [ ebx ]			;
					mov		dword ptr [ ebx ], eax;			;// Set the multiplied value
					mov		dword ptr [ carry ], edx		;// Set carry value to multiply
					jnc		skip_inc2						;// Don't increment the carry value if not set
					inc		dword ptr [ carry ]				;// Increment the carry value
				skip_inc2:
				}

				++a_val_ptr;
				++c_val_ptr;
			}

			++b_val_ptr;

			val_ptr[ bi_copy.val_length ] = carry;

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


void big_int_div_asm( BIG_INT *bi, unsigned long val )
{
	if ( bi != NULL && bi->val_length > 0 && val > 0 )
	{
		unsigned long long carry = 0;
		unsigned long *val_ptr;

		for ( unsigned long i = bi->val_length; i > 0; )
		{
			--i;

			val_ptr = bi->val + i;

			carry |= *val_ptr;

			// Avoids having to do a mod to get the remainder.
			__asm
			{
				mov		eax, dword ptr [ carry ]		;// Low order dividend
				mov		edx, dword ptr [ carry + 4 ]	;// High order dividend
				mov     ebx, dword ptr [ val ]			;// Divisor
				div		ebx								;// Divide the 64bit int by a 32bit int
				mov		esi, dword ptr [ val_ptr ]		;// Load the offset int array
				mov		[ esi ], eax					;// Store the quotient
				mov		dword ptr [ carry ], 0			;// Zero out the low order int
				mov		dword ptr [ carry + 4 ], edx	;// Store the remainder in the high order int
			}
		}

		if ( bi->val[ bi->val_length - 1 ] == 0 )
		{
			--bi->val_length;
		}
	}
}
