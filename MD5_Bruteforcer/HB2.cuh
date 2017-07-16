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

__global__
void HL01B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = gd_input_chunk[ ( blockIdx.x * blockDim.x + threadIdx.x ) * 2 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII0( trc, trd, tra, trb,       S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII0( trb, trc, trd, tra,       S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423af );	// 51 (ac = 0xab9423a7 + 0x08)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH0( trb, trc, trd, tra,       S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794396 );	// 15 (ac = 0xa679438e + 0x08)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG0( a, b, c, d,       S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33707de );	// 26 (ac = 0xc33707d6 + 0x08)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG0( d, a, b, c,       S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53814, tmp );	// 36 (ac = 0xfde5380c + 0x08)
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL02B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = gd_input_chunk[ ( blockIdx.x * blockDim.x + threadIdx.x ) * 2 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII0( trc, trd, tra, trb,       S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII0( trb, trc, trd, tra,       S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423b7 );	// 51 (ac = 0xab9423a7 + 0x10)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH0( trb, trc, trd, tra,       S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679439e );	// 15 (ac = 0xa679438e + 0x10)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG0( a, b, c, d,       S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33707e6 );	// 26 (ac = 0xc33707d6 + 0x10)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG0( d, a, b, c,       S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5381c, tmp );	// 36 (ac = 0xfde5380c + 0x10)
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL03B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = gd_input_chunk[ ( blockIdx.x * blockDim.x + threadIdx.x ) * 2 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII0( trc, trd, tra, trb,       S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII0( trb, trc, trd, tra,       S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423bf );	// 51 (ac = 0xab9423a7 + 0x18)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH0( trb, trc, trd, tra,       S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943a6 );	// 15 (ac = 0xa679438e + 0x18)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG0( a, b, c, d,       S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33707ee );	// 26 (ac = 0xc33707d6 + 0x18)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG0( d, a, b, c,       S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53824, tmp );	// 36 (ac = 0xfde5380c + 0x18)
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL04B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = gd_input_chunk[ ( blockIdx.x * blockDim.x + threadIdx.x ) * 2 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII0( trc, trd, tra, trb,       S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII0( trb, trc, trd, tra,       S44, 0x85845e51 );	// 56 (ac = 0x85845dd1 + 0x80)
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423c7 );	// 51 (ac = 0xab9423a7 + 0x20)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH0( trb, trc, trd, tra,       S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2 (ac = 0xf8fa0bcc + 0x80)
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0c4c;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943ae );	// 15 (ac = 0xa679438e + 0x20)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG0( a, b, c, d,       S21, 0xf61e25e2 );	// 17 (ac = 0xf61e2562 + 0x80)
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33707f6 );	// 26 (ac = 0xc33707d6 + 0x20)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG0( d, a, b, c,       S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5382c, tmp );	// 36 (ac = 0xfde5380c + 0x20)
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xa4beeac4, tmp );	// 37 (ac = 0xa4beea44 + 0x80)
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL05B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII0( trc, trd, tra, trb,       S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423cf );	// 51 (ac = 0xab9423a7 + 0x28)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH0( trb, trc, trd, tra,       S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943b6 );	// 15 (ac = 0xa679438e + 0x28)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33707fe );	// 26 (ac = 0xc33707d6 + 0x28)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG0( d, a, b, c,       S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53834, tmp );	// 36 (ac = 0xfde5380c + 0x28)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL06B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII0( trc, trd, tra, trb,       S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423d7 );	// 51 (ac = 0xab9423a7 + 0x30)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH0( trb, trc, trd, tra,       S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943be );	// 15 (ac = 0xa679438e + 0x30)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370806 );	// 26 (ac = 0xc33707d6 + 0x30)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG0( d, a, b, c,       S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5383c, tmp );	// 36 (ac = 0xfde5380c + 0x30)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL07B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII0( trc, trd, tra, trb,       S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423df );	// 51 (ac = 0xab9423a7 + 0x38)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH0( trb, trc, trd, tra,       S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943c6 );	// 15 (ac = 0xa679438e + 0x38)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337080e );	// 26 (ac = 0xc33707d6 + 0x38)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG0( d, a, b, c,       S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53844, tmp );	// 36 (ac = 0xfde5380c + 0x38)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL08B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII0( trc, trd, tra, trb,       S43, 0x2ad7d33b );	// 63 (ac = 0x2ad7d2bb + 0x80)
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423e7 );	// 51 (ac = 0xab9423a7 + 0x40)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH0( trb, trc, trd, tra,       S34, 0xc4ac56e5 );	// 48 (ac = 0xc4ac5665 + 0x80)
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3 (ac = 0xbcdb4dd9 + 0x80)
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4e59;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943ce );	// 15 (ac = 0xa679438e + 0x40)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370816 );	// 26 (ac = 0xc33707d6 + 0x40)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG0( d, a, b, c,       S22, 0xfcefa478 );	// 30 (ac = 0xfcefa3f8 + 0x80)
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5384c, tmp );	// 36 (ac = 0xfde5380c + 0x40)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL09B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423ef );	// 51 (ac = 0xab9423a7 + 0x48)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943d6 );	// 15 (ac = 0xa679438e + 0x48)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337081e );	// 26 (ac = 0xc33707d6 + 0x48)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53854, tmp );	// 36 (ac = 0xfde5380c + 0x48)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL10B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423f7 );	// 51 (ac = 0xab9423a7 + 0x50)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943de );	// 15 (ac = 0xa679438e + 0x50)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370826 );	// 26 (ac = 0xc33707d6 + 0x50)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5385c, tmp );	// 36 (ac = 0xfde5380c + 0x50)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL11B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9423ff );	// 51 (ac = 0xab9423a7 + 0x58)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943e6 );	// 15 (ac = 0xa679438e + 0x58)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337082e );	// 26 (ac = 0xc33707d6 + 0x58)
		GG0( c, d, a, b,       S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53864, tmp );	// 36 (ac = 0xfde5380c + 0x58)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL12B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII0( trd, tra, trb, trc,       S42, 0x8f0ccd12 );	// 54 (ac = 0x8f0ccc92 + 0x80)
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942407 );	// 51 (ac = 0xab9423a7 + 0x60)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4 (ac = 0xb18b7a77 + 0x80)
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7af7;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943ee );	// 15 (ac = 0xa679438e + 0x60)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370836 );	// 26 (ac = 0xc33707d6 + 0x60)
		GG0( c, d, a, b,       S23, 0xf4d50e07 );	// 27 (ac = 0xf4d50d87 + 0x80)
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5386c, tmp );	// 36 (ac = 0xfde5380c + 0x60)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xd4ef3105, tmp );	// 43 (ac = 0xd4ef3085 + 0x80)

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL13B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94240f );	// 51 (ac = 0xab9423a7 + 0x68)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943f6 );	// 15 (ac = 0xa679438e + 0x68)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337083e );	// 26 (ac = 0xc33707d6 + 0x68)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53874, tmp );	// 36 (ac = 0xfde5380c + 0x68)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL14B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942417 );	// 51 (ac = 0xab9423a7 + 0x70)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67943fe );	// 15 (ac = 0xa679438e + 0x70)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370846 );	// 26 (ac = 0xc33707d6 + 0x70)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5387c, tmp );	// 36 (ac = 0xfde5380c + 0x70)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL15B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94241f );	// 51 (ac = 0xab9423a7 + 0x78)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794406 );	// 15 (ac = 0xa679438e + 0x78)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337084e );	// 26 (ac = 0xc33707d6 + 0x78)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53884, tmp );	// 36 (ac = 0xfde5380c + 0x78)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL16B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII0( tra, trb, trc, trd,       S41, 0xf7537f02 );	// 61 (ac = 0xf7537e82 + 0x80)
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942427 );	// 51 (ac = 0xab9423a7 + 0x80)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF0( a, b, c, d,       S11, 0xf57c102f );	// 5 (ac = 0xf57c0faf + 0x80)
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679440e );	// 15 (ac = 0xa679438e + 0x80)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG0( b, c, d, a,       S24, 0xe7d3fc48 );	// 24 (ac = 0xe7d3fbc8 + 0x80)
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370856 );	// 26 (ac = 0xc33707d6 + 0x80)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5388c, tmp );	// 36 (ac = 0xfde5380c + 0x80)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb0( d, a, b, c,       S32, 0x4bded029, tmp );	// 38 (ac = 0x4bdecfa9 + 0x80)
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL17B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94242f );	// 51 (ac = 0xab9423a7 + 0x88)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794416 );	// 15 (ac = 0xa679438e + 0x88)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337085e );	// 26 (ac = 0xc33707d6 + 0x88)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53894, tmp );	// 36 (ac = 0xfde5380c + 0x88)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL18B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942437 );	// 51 (ac = 0xab9423a7 + 0x90)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679441e );	// 15 (ac = 0xa679438e + 0x90)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370866 );	// 26 (ac = 0xc33707d6 + 0x90)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5389c, tmp );	// 36 (ac = 0xfde5380c + 0x90)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL19B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94243f );	// 51 (ac = 0xab9423a7 + 0x98)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794426 );	// 15 (ac = 0xa679438e + 0x98)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337086e );	// 26 (ac = 0xc33707d6 + 0x98)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538a4, tmp );	// 36 (ac = 0xfde5380c + 0x98)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL20B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII0( trb, trc, trd, tra,       S44, 0xfc93a0b9 );	// 53 (ac = 0xfc93a039 + 0x80)
	RII0( trc, trd, tra, trb,       S43, 0xab942447 );	// 51 (ac = 0xab9423a7 + 0xa0)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF0( d, a, b, c,       S12, 0x4787c6aa );	// 6 (ac = 0x4787c62a + 0x80)
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679442e );	// 15 (ac = 0xa679438e + 0xa0)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG0( a, b, c, d,       S21, 0xd62f10dd );	// 21 (ac = 0xd62f105d + 0x80)
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370876 );	// 26 (ac = 0xc33707d6 + 0xa0)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0xfffa39c2, tmp );	// 33 (ac = 0xfffa3942 + 0x80)
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538ac, tmp );	// 36 (ac = 0xfde5380c + 0xa0)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL21B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94244f );	// 51 (ac = 0xab9423a7 + 0xa8)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794436 );	// 15 (ac = 0xa679438e + 0xa8)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337087e );	// 26 (ac = 0xc33707d6 + 0xa8)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538b4, tmp );	// 36 (ac = 0xfde5380c + 0xa8)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL22B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942457 );	// 51 (ac = 0xab9423a7 + 0xb0)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679443e );	// 15 (ac = 0xa679438e + 0xb0)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370886 );	// 26 (ac = 0xc33707d6 + 0xb0)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538bc, tmp );	// 36 (ac = 0xfde5380c + 0xb0)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL23B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94245f );	// 51 (ac = 0xab9423a7 + 0xb8)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794446 );	// 15 (ac = 0xa679438e + 0xb8)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337088e );	// 26 (ac = 0xc33707d6 + 0xb8)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538c4, tmp );	// 36 (ac = 0xfde5380c + 0xb8)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL24B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII0( trc, trd, tra, trb,       S43, 0xa3014394 );	// 59 (ac = 0xa3014314 + 0x80)
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942467 );	// 51 (ac = 0xab9423a7 + 0xc0)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF0( c, d, a, b,       S13, 0xa8304693 );	// 7 (ac = 0xa8304613 + 0x80)
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679444e );	// 15 (ac = 0xa679438e + 0xc0)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG0( d, a, b, c,       S22, 0xc040b3c0 );	// 18 (ac = 0xc040b340 + 0x80)
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370896 );	// 26 (ac = 0xc33707d6 + 0xc0)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538cc, tmp );	// 36 (ac = 0xfde5380c + 0xc0)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb0( b, c, d, a,       S34, 0x04881d85, tmp );	// 44 (ac = 0x4881d05 + 0x80)

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL25B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94246f );	// 51 (ac = 0xab9423a7 + 0xc8)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794456 );	// 15 (ac = 0xa679438e + 0xc8)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337089e );	// 26 (ac = 0xc33707d6 + 0xc8)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538d4, tmp );	// 36 (ac = 0xfde5380c + 0xc8)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL26B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942477 );	// 51 (ac = 0xab9423a7 + 0xd0)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679445e );	// 15 (ac = 0xa679438e + 0xd0)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708a6 );	// 26 (ac = 0xc33707d6 + 0xd0)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538dc, tmp );	// 36 (ac = 0xfde5380c + 0xd0)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL27B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94247f );	// 51 (ac = 0xab9423a7 + 0xd8)
	RII0( trd, tra, trb, trc,       S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794466 );	// 15 (ac = 0xa679438e + 0xd8)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708ae );	// 26 (ac = 0xc33707d6 + 0xd8)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538e4, tmp );	// 36 (ac = 0xfde5380c + 0xd8)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL28B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942487 );	// 51 (ac = 0xab9423a7 + 0xe0)
	RII0( trd, tra, trb, trc,       S42, 0x432b0017 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF0( b, c, d, a,       S14, 0xfd469581 );	// 8 (ac = 0xfd469501 + 0x80)
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679446e );	// 15 (ac = 0xa679438e + 0xe0)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708b6 );	// 26 (ac = 0xc33707d6 + 0xe0)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG0( c, d, a, b,       S23, 0x676f0359 );	// 31 (ac = 0x676f02d9 + 0x80)
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538ec, tmp );	// 36 (ac = 0xfde5380c + 0xe0)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0xf6bb4be0, tmp );	// 39 (ac = 0xf6bb4b60 + 0x80)
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL29B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94248f );	// 51 (ac = 0xab9423a7 + 0xe8)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794476 );	// 15 (ac = 0xa679438e + 0xe8)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708be );	// 26 (ac = 0xc33707d6 + 0xe8)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538f4, tmp );	// 36 (ac = 0xfde5380c + 0xe8)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL30B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942497 );	// 51 (ac = 0xab9423a7 + 0xf0)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679447e );	// 15 (ac = 0xa679438e + 0xf0)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708c6 );	// 26 (ac = 0xc33707d6 + 0xf0)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde538fc, tmp );	// 36 (ac = 0xfde5380c + 0xf0)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL31B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94249f );	// 51 (ac = 0xab9423a7 + 0xf8)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794486 );	// 15 (ac = 0xa679438e + 0xf8)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708ce );	// 26 (ac = 0xc33707d6 + 0xf8)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53904, tmp );	// 36 (ac = 0xfde5380c + 0xf8)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL32B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII0( tra, trb, trc, trd,       S41, 0x6fa87ecf );	// 57 (ac = 0x6fa87e4f + 0x80)
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424a7 );	// 51 (ac = 0xab9423a7 + 0x100)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF0( a, b, c, d,       S11, 0x69809958 );	// 9 (ac = 0x698098d8 + 0x80)
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679448e );	// 15 (ac = 0xa679438e + 0x100)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708d6 );	// 26 (ac = 0xc33707d6 + 0x100)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG0( b, c, d, a,       S24, 0x455a156d );	// 28 (ac = 0x455a14ed + 0x80)
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb0( d, a, b, c,       S32, 0x8771f701, tmp );	// 34 (ac = 0x8771f681 + 0x80)
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5390c, tmp );	// 36 (ac = 0xfde5380c + 0x100)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL33B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424af );	// 51 (ac = 0xab9423a7 + 0x108)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794496 );	// 15 (ac = 0xa679438e + 0x108)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708de );	// 26 (ac = 0xc33707d6 + 0x108)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53914, tmp );	// 36 (ac = 0xfde5380c + 0x108)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL34B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424b7 );	// 51 (ac = 0xab9423a7 + 0x110)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679449e );	// 15 (ac = 0xa679438e + 0x110)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708e6 );	// 26 (ac = 0xc33707d6 + 0x110)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5391c, tmp );	// 36 (ac = 0xfde5380c + 0x110)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL35B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424bf );	// 51 (ac = 0xab9423a7 + 0x118)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944a6 );	// 15 (ac = 0xa679438e + 0x118)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708ee );	// 26 (ac = 0xc33707d6 + 0x118)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53924, tmp );	// 36 (ac = 0xfde5380c + 0x118)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL36B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];

	// Round 4 reversal
	RII0( trb, trc, trd, tra,       S44, 0xeb86d411 );	// 64 (ac = 0xeb86d391 + 0x80)
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424c7 );	// 51 (ac = 0xab9423a7 + 0x120)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF0( d, a, b, c,       S12, 0x8b44f82f );	// 10 (ac = 0x8b44f7af + 0x80)
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944ae );	// 15 (ac = 0xa679438e + 0x120)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG0( a, b, c, d,       S21, 0x21e1ce66 );	// 25 (ac = 0x21e1cde6 + 0x80)
		GG0( d, a, b, c,       S22, 0xc33708f6 );	// 26 (ac = 0xc33707d6 + 0x120)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5392c, tmp );	// 36 (ac = 0xfde5380c + 0x120)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa0( a, b, c, d,       S31, 0xd9d4d0b9, tmp );	// 45 (ac = 0xd9d4d039 + 0x80)

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL37B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424cf );	// 51 (ac = 0xab9423a7 + 0x128)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944b6 );	// 15 (ac = 0xa679438e + 0x128)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc33708fe );	// 26 (ac = 0xc33707d6 + 0x128)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53934, tmp );	// 36 (ac = 0xfde5380c + 0x128)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL38B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424d7 );	// 51 (ac = 0xab9423a7 + 0x130)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944be );	// 15 (ac = 0xa679438e + 0x130)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370906 );	// 26 (ac = 0xc33707d6 + 0x130)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5393c, tmp );	// 36 (ac = 0xfde5380c + 0x130)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL39B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424df );	// 51 (ac = 0xab9423a7 + 0x138)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944c6 );	// 15 (ac = 0xa679438e + 0x138)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337090e );	// 26 (ac = 0xc33707d6 + 0x138)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53944, tmp );	// 36 (ac = 0xfde5380c + 0x138)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL40B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII0( trc, trd, tra, trb,       S43, 0xffeff4fd );	// 55 (ac = 0xffeff47d + 0x80)
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424e7 );	// 51 (ac = 0xab9423a7 + 0x140)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF0( c, d, a, b,       S13, 0xffff5c31 );	// 11 (ac = 0xffff5bb1 + 0x80)
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944ce );	// 15 (ac = 0xa679438e + 0x140)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG0( d, a, b, c,       S22, 0x024414d3 );	// 22 (ac = 0x02441453 + 0x80)
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370916 );	// 26 (ac = 0xc33707d6 + 0x140)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5394c, tmp );	// 36 (ac = 0xfde5380c + 0x140)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb0( b, c, d, a,       S34, 0xbebfbcf0, tmp );	// 40 (ac = 0xbebfbc70 + 0x80)
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL41B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424ef );	// 51 (ac = 0xab9423a7 + 0x148)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944d6 );	// 15 (ac = 0xa679438e + 0x148)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337091e );	// 26 (ac = 0xc33707d6 + 0x148)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53954, tmp );	// 36 (ac = 0xfde5380c + 0x148)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL42B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424f7 );	// 51 (ac = 0xab9423a7 + 0x150)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944de );	// 15 (ac = 0xa679438e + 0x150)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370926 );	// 26 (ac = 0xc33707d6 + 0x150)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5395c, tmp );	// 36 (ac = 0xfde5380c + 0x150)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL43B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab9424ff );	// 51 (ac = 0xab9423a7 + 0x158)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944e6 );	// 15 (ac = 0xa679438e + 0x158)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337092e );	// 26 (ac = 0xc33707d6 + 0x158)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53964, tmp );	// 36 (ac = 0xfde5380c + 0x158)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL44B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII0( trd, tra, trb, trc,       S42, 0xbd3af2b5 );	// 62 (ac = 0xbd3af235 + 0x80)
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942507 );	// 51 (ac = 0xab9423a7 + 0x160)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF0( b, c, d, a,       S14, 0x895cd83e );	// 12 (ac = 0x895cd7be + 0x80)
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944ee );	// 15 (ac = 0xa679438e + 0x160)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG0( c, d, a, b,       S23, 0x265e5ad1 );	// 19 (ac = 0x265e5a51 + 0x80)
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370936 );	// 26 (ac = 0xc33707d6 + 0x160)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa0( c, d, a, b,       S33, 0x6d9d61a2, tmp );	// 35 (ac = 0x6d9d6122 + 0x80)
		HHb0( b, c, d, a,       S34, 0xfde5396c, tmp );	// 36 (ac = 0xfde5380c + 0x160)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL45B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94250f );	// 51 (ac = 0xab9423a7 + 0x168)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944f6 );	// 15 (ac = 0xa679438e + 0x168)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337093e );	// 26 (ac = 0xc33707d6 + 0x168)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53974, tmp );	// 36 (ac = 0xfde5380c + 0x168)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL46B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942517 );	// 51 (ac = 0xab9423a7 + 0x170)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa67944fe );	// 15 (ac = 0xa679438e + 0x170)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370946 );	// 26 (ac = 0xc33707d6 + 0x170)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5397c, tmp );	// 36 (ac = 0xfde5380c + 0x170)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL47B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94251f );	// 51 (ac = 0xab9423a7 + 0x178)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794506 );	// 15 (ac = 0xa679438e + 0x178)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337094e );	// 26 (ac = 0xc33707d6 + 0x178)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53984, tmp );	// 36 (ac = 0xfde5380c + 0x178)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL48B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII0( tra, trb, trc, trd,       S41, 0x655b5a43 );	// 53 (ac = 0x655b59c3 + 0x80)
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942527 );	// 51 (ac = 0xab9423a7 + 0x180)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF0( a, b, c, d,       S11, 0x6b9011a2 );	// 13 (ac = 0x6b901122 + 0x80)
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679450e );	// 15 (ac = 0xa679438e + 0x180)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370956 );	// 26 (ac = 0xc33707d6 + 0x180)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG0( b, c, d, a,       S24, 0x8d2a4d0a );	// 32 (ac = 0x8d2a4c8a + 0x80)

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5398c, tmp );	// 36 (ac = 0xfde5380c + 0x180)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb0( d, a, b, c,       S32, 0xe6db9a65, tmp );	// 46 (ac = 0xe6db99e5 + 0x80)

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL49B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];
	register unsigned int in12 = gd_input_chunk2[ 10 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII ( tra, trb, trc, trd, in12, S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94252f );	// 51 (ac = 0xab9423a7 + 0x188)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF ( a, b, c, d, in12, S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794516 );	// 15 (ac = 0xa679438e + 0x188)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337095e );	// 26 (ac = 0xc33707d6 + 0x188)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG ( b, c, d, a, in12, S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde53994, tmp );	// 36 (ac = 0xfde5380c + 0x188)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb ( d, a, b, c, in12, S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;
						gd_found_hash_input[ 12 ] = in12;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL50B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];
	register unsigned int in12 = gd_input_chunk2[ 10 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII ( tra, trb, trc, trd, in12, S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942537 );	// 51 (ac = 0xab9423a7 + 0x190)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF ( a, b, c, d, in12, S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679451e );	// 15 (ac = 0xa679438e + 0x190)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370966 );	// 26 (ac = 0xc33707d6 + 0x190)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG ( b, c, d, a, in12, S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde5399c, tmp );	// 36 (ac = 0xfde5380c + 0x190)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb ( d, a, b, c, in12, S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;
						gd_found_hash_input[ 12 ] = in12;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL51B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];
	register unsigned int in12 = gd_input_chunk2[ 10 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII ( tra, trb, trc, trd, in12, S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94253f );	// 51 (ac = 0xab9423a7 + 0x198)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF ( a, b, c, d, in12, S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794526 );	// 15 (ac = 0xa679438e + 0x198)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337096e );	// 26 (ac = 0xc33707d6 + 0x198)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG ( b, c, d, a, in12, S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde539a4, tmp );	// 36 (ac = 0xfde5380c + 0x198)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb ( d, a, b, c, in12, S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;
						gd_found_hash_input[ 12 ] = in12;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL52B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];
	register unsigned int in12 = gd_input_chunk2[ 10 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII0( trb, trc, trd, tra,       S44, 0x4e081221 );	// 60 (ac = 0x4e0811a1 + 0x80)
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII ( tra, trb, trc, trd, in12, S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942547 );	// 51 (ac = 0xab9423a7 + 0x1a0)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF ( a, b, c, d, in12, S11, 0x6b901122 );	// 13
		FF0( d, a, b, c,       S12, 0xfd987213 );	// 14 (ac = 0xfd987193 + 0x80)
		FF0( c, d, a, b,       S13, 0xa679452e );	// 15 (ac = 0xa679438e + 0x1a0)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370976 );	// 26 (ac = 0xc33707d6 + 0x1a0)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG0( a, b, c, d,       S21, 0xa9e3e985 );	// 29 (ac = 0xa9e3e905 + 0x80)
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG ( b, c, d, a, in12, S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde539ac, tmp );	// 36 (ac = 0xfde5380c + 0x1a0)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa0( a, b, c, d,       S31, 0x289b7f46, tmp );	// 41 (ac = 0x289b7ec6 + 0x80)
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb ( d, a, b, c, in12, S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;
						gd_found_hash_input[ 12 ] = in12;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL53B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];
	register unsigned int in12 = gd_input_chunk2[ 10 ];
	register unsigned int in13 = gd_input_chunk2[ 11 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII ( trb, trc, trd, tra, in13, S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII ( tra, trb, trc, trd, in12, S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94254f );	// 51 (ac = 0xab9423a7 + 0x1a8)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF ( a, b, c, d, in12, S11, 0x6b901122 );	// 13
		FF ( d, a, b, c, in13, S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794536 );	// 15 (ac = 0xa679438e + 0x1a8)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337097e );	// 26 (ac = 0xc33707d6 + 0x1a8)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG ( a, b, c, d, in13, S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG ( b, c, d, a, in12, S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde539b4, tmp );	// 36 (ac = 0xfde5380c + 0x1a8)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa ( a, b, c, d, in13, S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb ( d, a, b, c, in12, S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;
						gd_found_hash_input[ 12 ] = in12;
						gd_found_hash_input[ 13 ] = in13;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL54B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];
	register unsigned int in12 = gd_input_chunk2[ 10 ];
	register unsigned int in13 = gd_input_chunk2[ 11 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII ( trb, trc, trd, tra, in13, S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII ( tra, trb, trc, trd, in12, S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab942557 );	// 51 (ac = 0xab9423a7 + 0x1b0)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF ( a, b, c, d, in12, S11, 0x6b901122 );	// 13
		FF ( d, a, b, c, in13, S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa679453e );	// 15 (ac = 0xa679438e + 0x1b0)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc3370986 );	// 26 (ac = 0xc33707d6 + 0x1b0)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG ( a, b, c, d, in13, S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG ( b, c, d, a, in12, S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde539bc, tmp );	// 36 (ac = 0xfde5380c + 0x1b0)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa ( a, b, c, d, in13, S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb ( d, a, b, c, in12, S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;
						gd_found_hash_input[ 12 ] = in12;
						gd_found_hash_input[ 13 ] = in13;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}

__global__
void HL55B02()
{
	register unsigned int in00, a, b, c, d, ra, rb, rc, rd, tmp, i;	// Don't initialize.

	register unsigned int *input = gd_input_chunk + ( blockIdx.x * blockDim.x + threadIdx.x ) * 2;

	// Pregenerated input. Looks like 0xFFFFFF00. The last byte is set in the loop below.
	register unsigned int in00a = input[ 0 ];

	// Ignore any overflow input.
	if ( !in00a )
	{
		return;
	}

	register unsigned int in01 = input[ 1 ];

	register unsigned char css = gd_character_set_size;

	register unsigned int tra = gd_hash_value[ 0 ];
	register unsigned int trb = gd_hash_value[ 1 ];
	register unsigned int trc = gd_hash_value[ 2 ];
	register unsigned int trd = gd_hash_value[ 3 ];

	register unsigned int in02 = gd_input_chunk2[ 0 ];
	register unsigned int in03 = gd_input_chunk2[ 1 ];
	register unsigned int in04 = gd_input_chunk2[ 2 ];
	register unsigned int in05 = gd_input_chunk2[ 3 ];
	register unsigned int in06 = gd_input_chunk2[ 4 ];
	register unsigned int in07 = gd_input_chunk2[ 5 ];
	register unsigned int in08 = gd_input_chunk2[ 6 ];
	register unsigned int in09 = gd_input_chunk2[ 7 ];
	register unsigned int in10 = gd_input_chunk2[ 8 ];
	register unsigned int in11 = gd_input_chunk2[ 9 ];
	register unsigned int in12 = gd_input_chunk2[ 10 ];
	register unsigned int in13 = gd_input_chunk2[ 11 ];

	// Round 4 reversal
	RII ( trb, trc, trd, tra, in09, S44, 0xeb86d391 );	// 64
	RII ( trc, trd, tra, trb, in02, S43, 0x2ad7d2bb );	// 63
	RII ( trd, tra, trb, trc, in11, S42, 0xbd3af235 );	// 62
	RII ( tra, trb, trc, trd, in04, S41, 0xf7537e82 );	// 61
	RII ( trb, trc, trd, tra, in13, S44, 0x4e0811a1 );	// 60
	RII ( trc, trd, tra, trb, in06, S43, 0xa3014314 );	// 59
	RII0( trd, tra, trb, trc,       S42, 0xfe2ce6e0 );	// 58
	RII ( tra, trb, trc, trd, in08, S41, 0x6fa87e4f );	// 57
	RII ( trb, trc, trd, tra, in01, S44, 0x85845dd1 );	// 56
	RII ( trc, trd, tra, trb, in10, S43, 0xffeff47d );	// 55
	RII ( trd, tra, trb, trc, in03, S42, 0x8f0ccc92 );	// 54
	RII ( tra, trb, trc, trd, in12, S41, 0x655b59c3 );	// 53
	RII ( trb, trc, trd, tra, in05, S44, 0xfc93a039 );	// 53
	RII0( trc, trd, tra, trb,       S43, 0xab94255f );	// 51 (ac = 0xab9423a7 + 0x1b8)
	RII ( trd, tra, trb, trc, in07, S42, 0x432aff97 );	// 50
	RII0( tra, trb, trc, trd,       S41, 0xf4292244 );	// 49

	register unsigned int tmp2 = trc ^ trd;

	// Round 3 reversal
	RHH ( trb, trc, trd, tra, in02, S34, 0xc4ac5665 );	// 48
	RHH0( trc, trd, tra, trb,       S33, 0x1fa27cf8 );	// 47

	// We're going to hash values in chunks of n^4 worth of values.
	// Rather than generate n^4 values (and subsequently call n^4 threads), we can simply generate n^3 values/threads and perform a loop to get the remaining values.
	// Too many blocks/threads causes a bottleneck and this way allows us to hit the GPU's throughput sweet spot.
	// At least that's been my empirical observation.
	for ( i = 0; i < css; ++i )
	{
		// Add the last byte to our pregenerated values.
		in00 = in00a | gd_character_set[ i ];

		// Complete our reversal from above.
		rd = trd;
		ra = tra - in00;
		rb = trb - ( ra ^ tmp2 );
		rc = trc - ( ra ^ rb ^ rd );

		// Round 1
		// The first four steps of round 1 can be partially calculated beforehand using the magic numbers.
		// 1
		a = 0xd76aa477 + in00;
		a = ROTATE_LEFT( a, 7 ) + 0xefcdab89;
		// 2
		d = ( 0x98badcfe ^ ( a & 0x77777777 ) ) + 0xf8fa0bcc + in01;
		d = ROTATE_LEFT( d, 12 ) + a;

		// 3
		c = ( ( ( a ^ 0xefcdab89 ) & d ) ^ 0xefcdab89 ) + 0xbcdb4dd9 + in02;
		c = ROTATE_LEFT( c, 17 ) + d;

		// 4
		b = ( ( ( d ^ a ) & c ) ^ a ) + 0xb18b7a77 + in03;
		b = ROTATE_LEFT( b, 22 ) + c;

		FF ( a, b, c, d, in04, S11, 0xf57c0faf );	// 5
		FF ( d, a, b, c, in05, S12, 0x4787c62a );	// 6
		FF ( c, d, a, b, in06, S13, 0xa8304613 );	// 7
		FF ( b, c, d, a, in07, S14, 0xfd469501 );	// 8
		FF ( a, b, c, d, in08, S11, 0x698098d8 );	// 9
		FF ( d, a, b, c, in09, S12, 0x8b44f7af );	// 10
		FF ( c, d, a, b, in10, S13, 0xffff5bb1 );	// 11
		FF ( b, c, d, a, in11, S14, 0x895cd7be );	// 12
		FF ( a, b, c, d, in12, S11, 0x6b901122 );	// 13
		FF ( d, a, b, c, in13, S12, 0xfd987193 );	// 14
		FF0( c, d, a, b,       S13, 0xa6794546 );	// 15 (ac = 0xa679438e + 0x1b8)
		FF0( b, c, d, a,       S14, 0x49b40821 );	// 16

		// Round 2
		GG ( a, b, c, d, in01, S21, 0xf61e2562 );	// 17
		GG ( d, a, b, c, in06, S22, 0xc040b340 );	// 18
		GG ( c, d, a, b, in11, S23, 0x265e5a51 );	// 19
		GG ( b, c, d, a, in00, S24, 0xe9b6c7aa );	// 20
		GG ( a, b, c, d, in05, S21, 0xd62f105d );	// 21
		GG ( d, a, b, c, in10, S22, 0x02441453 );	// 22
		GG0( c, d, a, b,       S23, 0xd8a1e681 );	// 23
		GG ( b, c, d, a, in04, S24, 0xe7d3fbc8 );	// 24
		GG ( a, b, c, d, in09, S21, 0x21e1cde6 );	// 25
		GG0( d, a, b, c,       S22, 0xc337098e );	// 26 (ac = 0xc33707d6 + 0x1b8)
		GG ( c, d, a, b, in03, S23, 0xf4d50d87 );	// 27
		GG ( b, c, d, a, in08, S24, 0x455a14ed );	// 28
		GG ( a, b, c, d, in13, S21, 0xa9e3e905 );	// 29
		GG ( d, a, b, c, in02, S22, 0xfcefa3f8 );	// 30
		GG ( c, d, a, b, in07, S23, 0x676f02d9 );	// 31
		GG ( b, c, d, a, in12, S24, 0x8d2a4c8a );	// 32

		// Round 3
		tmp = b ^ c;
		HHa ( a, b, c, d, in05, S31, 0xfffa3942, tmp );	// 33
		HHb ( d, a, b, c, in08, S32, 0x8771f681, tmp );	// 34
		tmp = d ^ a;
		HHa ( c, d, a, b, in11, S33, 0x6d9d6122, tmp );	// 35
		HHb0( b, c, d, a,       S34, 0xfde539c4, tmp );	// 36 (ac = 0xfde5380c + 0x1b8)
		tmp = b ^ c;
		HHa ( a, b, c, d, in01, S31, 0xa4beea44, tmp );	// 37
		HHb ( d, a, b, c, in04, S32, 0x4bdecfa9, tmp );	// 38
		tmp = d ^ a;
		HHa ( c, d, a, b, in07, S33, 0xf6bb4b60, tmp );	// 39
		HHb ( b, c, d, a, in10, S34, 0xbebfbc70, tmp );	// 40
		tmp = b ^ c;
		HHa ( a, b, c, d, in13, S31, 0x289b7ec6, tmp );	// 41
		HHb ( d, a, b, c, in00, S32, 0xeaa127fa, tmp );	// 42
		tmp = d ^ a;
		HHa ( c, d, a, b, in03, S33, 0xd4ef3085, tmp );	// 43

		if ( c == rc )
		{
			HHb ( b, c, d, a, in06, S34, 0x04881d05, tmp );	// 44

			if ( b == rb )
			{
				tmp = b ^ c;
				HHa ( a, b, c, d, in09, S31, 0xd9d4d039, tmp );	// 45

				if ( a == ra )
				{
					HHb ( d, a, b, c, in12, S32, 0xe6db99e5, tmp );	// 46

					if ( d == rd )
					{
						gd_found_hash_input[ 0 ] = in00;
						gd_found_hash_input[ 1 ] = in01;
						gd_found_hash_input[ 2 ] = in02;
						gd_found_hash_input[ 3 ] = in03;
						gd_found_hash_input[ 4 ] = in04;
						gd_found_hash_input[ 5 ] = in05;
						gd_found_hash_input[ 6 ] = in06;
						gd_found_hash_input[ 7 ] = in07;
						gd_found_hash_input[ 8 ] = in08;
						gd_found_hash_input[ 9 ] = in09;
						gd_found_hash_input[ 10 ] = in10;
						gd_found_hash_input[ 11 ] = in11;
						gd_found_hash_input[ 12 ] = in12;
						gd_found_hash_input[ 13 ] = in13;

						gd_hash_found = true;

						return;
					}
				}
			}
		}
	}
}
