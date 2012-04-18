/*  2000.09.01     */
/*  CryptNET       */
/*  vab@dublin.ie  */

#include "rc5.h"

int test_128(void);
int test_attack_128(void);
int attack_128(void);


int test_128(void)
{
        int i, j, k, LL, T;
        RC5_WORD    L[256/WW];  /* Based on max key size  */
	RC5_WORD    K[4];       /* Storage for Secret Key */
        RC5_WORD    A, B;

        int b = 16;       /* Key Length in Bytes */
        int R = 12;       /* Rounds */
        RC5_WORD S[26];   /* S Table For Expanded Key */

        RC5_WORD pt[2];
        RC5_WORD iv[2];

        LL = 4;  /* LL is number of elements used in L. */

        /* Backwards little edian style baby, owww yeah */

        /* Secret Key */
        L[0] = 0xb92a6cb1;
        L[1] = 0x485efb74;
	L[2] = 0xd7658a7f;
	L[3] = 0x620ce4f9;

	K[0] = L[0];
	K[1] = L[1];
	K[2] = L[2];
	K[3] = L[3];

        /* Intilization Vector */
        iv[0] = 0x509d3c0b; 
        iv[1] = 0xf1f906fd;

        /* Plain Text */
        pt[0] = 0x20656854;
        pt[1] = 0x6e6b6e75;

        /* CBC so we Xor */
        pt[0] = pt[0] ^ iv[0];
        pt[1] = pt[1] ^ iv[1];

        T = 26;

        /*
           seed the S Array (key expansion array) with
           psudo random numbers
        */
        S[0] = Pw;
        for (i = 1 ; i < T ; i++)
        {
                S[i] = S[i-1] + Qw;
        }

        i = j = 0;
        A = B = 0;
        k = 3 * T;  /* Secret key len < expanded key. */

        /*
          Mix the secret key in with the psudo random numbers
          in the S Array
        */

        for ( ; k > 0 ; k--)
        {
                A = ROTL(S[i] + A + B, 3, W);
                S[i] = A;
                B = ROTL(L[j] + A + B, A + B, W);
                L[j] = B;
                i = (i + 1) % T;
                j = (j + 1) % LL;
        }

        /* Encrypt */
        A = pt[0];
        B = pt[1];

        A = A + S[0];
        B = B + S[1];

        for (i = 1 ; i <= R ; i++)
        {
                A = A ^ B;
                A = ROTL(A, B, W) + S[2*i];
                B = B ^ A;
                B = ROTL(B, A, W) + S[(2*i)+1];
        }

        if(A == 0xe9ae4ede)
        {
                if(B == 0xc285f56c)
                {
                        return 0;
                }

        }
        printf("Failure\n");
	
	
        return 0;
}


int test_attack_128(void)
{
        int i, j, k, LL, T;
        RC5_WORD    L[256/WW];  /* Based on max key size */
        RC5_WORD    A, B;

        int b = 16;      /* Key Length in Bytes */
        int R = 12;      /* Rounds */
        RC5_WORD S[26];  /* S Table For Expanded Key */

        /* I need a file pointer to random */
        FILE *dr;

	RC5_WORD K[4];  /* key storage */
        RC5_WORD pt[2];
        RC5_WORD iv[2];

	int rslt = 0;

        LL = 4;  /* LL is number of elements used in L. */

        /* Backwards little edian style baby, owww yeah */

        /* Secret Key */
        L[0] = 0x00000000;
        L[1] = 0x00000000;
	L[2] = 0x00000000;
	L[3] = 0x00000000;

        /* Intilization Vector */
        iv[0] = 0x509d3c0b;
        iv[1] = 0xf1f906fd;

        /* Plain Text */
        pt[0] = 0x20656854;
        pt[1] = 0x6e6b6e75;

        /* CBC so we Xor */
        pt[0] = pt[0] ^ iv[0];
        pt[1] = pt[1] ^ iv[1];

        printf("CryptNET:  RSA Labs RC5-128 Challenge Full Test Client\n");
        printf("\n");

        T = 26;

        if(NULL == (dr = fopen("/dev/urandom", "r")))
	{
		fprintf(stderr,"Error: Failed to open /dev/urandom device\n");
	}
	else
	{
		rslt = fread(K,4,4,dr);
		if(rslt != 4)
		{
			fprintf(stderr,"Error: Failed to read from /dev/urandom device\n");
		}
		fclose(dr);
	}
	/* We should just continue on if we fail and run with what ever value is found
	   in K.  That value is probably old data left in memory, which is most likely
	   reasonably random.  Depending on the OS, it may be zero'd or 0xff'd space,
	   which isn't as nice, but is better than exiting and not running at all.
	*/

        printf("Starting at: 0x%0.8x:0x%0.8x:0x%0.8x:0x%0.8x\n", K[0], K[1], K[2], K[3]);

        while(1) /* crack */
        {
		L[0] = K[0];
		L[1] = K[1];
		L[2] = K[2];
		L[3] = K[3];

	        /*
        	   seed the S Array (key expansion array) with
 	           psudo random numbers
		*/
 		S[0] = Pw;
    	    	for (i = 1 ; i < T ; i++)
    	    	{
       	        	S[i] = S[i-1] + Qw;
      		}

                i = j = 0;
                A = B = 0;
                k = 3 * T;  /* Secret key len < expanded key. */

                /*
                        Mix the secret key in with the psudo random numbers
                        in the S Array
                */

                for ( ; k > 0 ; k--)
                {
                        A = ROTL(S[i] + A + B, 3, W);
                        S[i] = A;
                        B = ROTL(L[j] + A + B, A + B, W);
                        L[j] = B;
                        i = (i + 1) % T;
                        j = (j + 1) % LL;
                }

                /* Encrypt */
                A = pt[0];
                B = pt[1];

                A = A + S[0];
                B = B + S[1];

                for (i = 1 ; i <= R ; i++)
                {
                        A = A ^ B;
                        A = ROTL(A, B, W) + S[2*i];
                        B = B ^ A;
                        B = ROTL(B, A, W) + S[(2*i)+1];
                }

		/*
		  Compare to cyphertext.
		*/
                if(A == 0xe9ae4ede)
                {
                        if(B == 0xc285f56c)
                        {
                                printf("Secret Key Candidate Found:\t");
                                printf("0x%0.8x:0x%0.8x:0x%0.8x:0x%0.8x\n\n", K[0], K[1], K[2], K[3]);
                                return 0;
                        }
                }

		if(K[0]!=0xffffffff)
		{
                	K[0]++;
		}
                else
                {
			if(K[1]!=0xffffffff)
			{
				K[1]++;
				K[0]=0x00000000;
			}
			else
			{
				if(K[2]!=0xffffffff)
				{
					K[2]++;
					K[1]=0x00000000;
					K[0]=0x00000000;
				}
				else
				{
					if(K[3]!=0xffffffff)
					{
						K[3]++;
						K[2]=0x00000000;
						K[1]=0x00000000;
						K[0]=0x00000000;
					}
					else
					{
						K[3]=0x00000000;
                        			K[2]=0x00000000;
                        			K[1]=0x00000000;
						K[0]=0x00000000;
					}
				}
			}
                }
        }
        return 0;
}


int attack_128(void)
{
        int i, j, k, LL, T;
        RC5_WORD    L[256/WW];  /* Based on max key size */
        RC5_WORD    A, B;

        int b = 16;      /* Key Length in Bytes */
        int R = 12;      /* Rounds */
        RC5_WORD S[26];  /* S Table For Expanded Key */

        /* I need a file pointer to random */
        FILE *dr;

	RC5_WORD K[4];  /* key storage */
        RC5_WORD pt[2];
        RC5_WORD iv[2];

	int rslt = 0;

        LL = 4;  /* LL is number of elements used in L. */

        /* Backwards little edian style baby, owww yeah */

        /* Secret Key */
        L[0] = 0x00000000;
        L[1] = 0x00000000;
	L[2] = 0x00000000;
	L[3] = 0x00000000;

        /* Intilization Vector */
        iv[0] = 0xe8008ba7;
        iv[1] = 0x5d2fe615;

        /* Plain Text */
        pt[0] = 0x20656854;
        pt[1] = 0x6e6b6e75;

        /* CBC so we Xor */
        pt[0] = pt[0] ^ iv[0];
        pt[1] = pt[1] ^ iv[1];

        printf("CryptNET:  RSA Labs RC5-128 Challenge Full Attack Client\n");
        printf("\n");

        T = 26;

        if(NULL == (dr = fopen("/dev/urandom", "r")))
	{
		fprintf(stderr,"Error: Failed to open /dev/urandom device\n");
	}
	else
	{
		rslt = fread(K,4,4,dr);
		if(rslt != 4)
		{
			fprintf(stderr,"Error: Failed to read from /dev/urandom device\n");
		}
		fclose(dr);
	}
	/* We should just continue on if we fail and run with what ever value is found
	   in K.  That value is probably old data left in memory, which is most likely
	   reasonably random.  Depending on the OS, it may be zero'd or 0xff'd space,
	   which isn't as nice, but is better than exiting and not running at all.
	*/

        printf("Starting at: 0x%0.8x:0x%0.8x:0x%0.8x:0x%0.8x\n", K[0], K[1], K[2], K[3]);

        while(1) /* crack */
        {
		L[0] = K[0];
		L[1] = K[1];
		L[2] = K[2];
		L[3] = K[3];

	        /*
        	   seed the S Array (key expansion array) with
 	           psudo random numbers
		*/
 		S[0] = Pw;
    	    	for (i = 1 ; i < T ; i++)
    	    	{
       	        	S[i] = S[i-1] + Qw;
      		}

                i = j = 0;
                A = B = 0;
                k = 3 * T;  /* Secret key len < expanded key. */

                /*
                        Mix the secret key in with the psudo random numbers
                        in the S Array
                */

                for ( ; k > 0 ; k--)
                {
                        A = ROTL(S[i] + A + B, 3, W);
                        S[i] = A;
                        B = ROTL(L[j] + A + B, A + B, W);
                        L[j] = B;
                        i = (i + 1) % T;
                        j = (j + 1) % LL;
                }

                /* Encrypt */
                A = pt[0];
                B = pt[1];

                A = A + S[0];
                B = B + S[1];

                for (i = 1 ; i <= R ; i++)
                {
                        A = A ^ B;
                        A = ROTL(A, B, W) + S[2*i];
                        B = B ^ A;
                        B = ROTL(B, A, W) + S[(2*i)+1];
                }

		/*
		  Compare to cyphertext.
		*/
                if(A == 0x72273bd9)
                {
                        if(B == 0xcb658a11)
                        {
                                printf("Secret Key Candidate Found:\t");
                                printf("0x%0.8x:0x%0.8x:0x%0.8x:0x%0.8x\n\n", K[0], K[1], K[2], K[3]);
                                return 0;
                        }
                }

		if(K[0]!=0xffffffff)
		{
                	K[0]++;
		}
                else
                {
			if(K[1]!=0xffffffff)
			{
				K[1]++;
				K[0]=0x00000000;
			}
			else
			{
				if(K[2]!=0xffffffff)
				{
					K[2]++;
					K[1]=0x00000000;
					K[0]=0x00000000;
				}
				else
				{
					if(K[3]!=0xffffffff)
					{
						K[3]++;
						K[2]=0x00000000;
						K[1]=0x00000000;
						K[0]=0x00000000;
					}
					else
					{
						K[3]=0x00000000;
                        			K[2]=0x00000000;
                        			K[1]=0x00000000;
						K[0]=0x00000000;
					}
				}
			}
                }
        }
        return 0;
}
