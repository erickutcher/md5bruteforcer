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

#ifndef _BIG_INT
#define _BIG_INT

#define BUFFER_SIZE 32

struct BIG_INT
{
	unsigned long *val;
	unsigned long val_length;	// Length of the number.
	unsigned long val_size;		// Size in ints of the val array.
};

void big_int_init( BIG_INT *bi );
void big_int_init( BIG_INT *bi, unsigned long val );
void big_int_init( BIG_INT *bi, unsigned long long val );
void big_int_init( BIG_INT *bi1, BIG_INT *bi2 );
void big_int_uninit( BIG_INT *bi );
int big_int_cmp( BIG_INT *bi, unsigned long val, unsigned long offset = 0 );
int big_int_cmp( BIG_INT *bi, unsigned long long val, unsigned long offset = 0 );
int big_int_cmp( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset1 = 0, unsigned long offset2 = 0 );
void big_int_set( BIG_INT *bi, unsigned long val );
void big_int_set( BIG_INT *bi, unsigned long long val );
void big_int_set( BIG_INT *bi1, BIG_INT *bi2 );
void big_int_shift_left( BIG_INT *bi, unsigned long val );
void big_int_shift_right( BIG_INT *bi, unsigned long val );
void big_int_add( BIG_INT *bi, unsigned long val, unsigned long offset = 0 );
void big_int_add( BIG_INT *bi, unsigned long long val, unsigned long offst = 0 );
void big_int_add( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset = 0 );
void big_int_sub( BIG_INT *bi, unsigned long val, unsigned long offset = 0 );
void big_int_sub( BIG_INT *bi, unsigned long long val, unsigned long offset = 0 );
void big_int_sub( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset = 0 );
void big_int_mul( BIG_INT *bi, unsigned long val );
void big_int_mul( BIG_INT *bi, unsigned long long val );
void big_int_mul( BIG_INT *bi1, BIG_INT *bi2 );
void big_int_div( BIG_INT *bi, unsigned long val );
void big_int_div( BIG_INT *bi1, BIG_INT *bi2 );
void big_int_pow( BIG_INT *bi, unsigned long val );
void big_int_print( BIG_INT *bi );
double big_int_simple_percent( BIG_INT *bi1, BIG_INT *bi2 );

#endif
