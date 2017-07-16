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

#ifndef _BIG_INT_ASM
#define _BIG_INT_ASM

#include "big_int.h"

void big_int_add_asm( BIG_INT *bi, unsigned long val, unsigned long offset = 0 );
void big_int_add_asm( BIG_INT *bi, unsigned long long val, unsigned long offset = 0 );
void big_int_add_asm( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset = 0 );
void big_int_sub_asm( BIG_INT *bi, unsigned long val, unsigned long offset = 0 );
void big_int_sub_asm( BIG_INT *bi, unsigned long long val, unsigned long offset = 0 );
void big_int_sub_asm( BIG_INT *bi1, BIG_INT *bi2, unsigned long offset = 0 );
void big_int_mul_asm( BIG_INT *bi, unsigned long val );
void big_int_mul_asm( BIG_INT *bi, unsigned long long val );
void big_int_mul_asm( BIG_INT *bi1, BIG_INT *bi2 );
void big_int_div_asm( BIG_INT *bi, unsigned long val );

#endif
