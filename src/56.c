/*  2000.09.01     */
/*  CryptNET       */
/*  vab@dublin.ie  */

#include "rc5.h"

int test_56(void);
int test_attack_56(void);
int attack_56(void);



int test_56(void)
{
        int i, j, k, LL, T;
        RC5_WORD    L[256/WW];  /* Based on max key size */
        RC5_WORD    A, B;

        int b = 7;       /* Key Length in Bytes */
        int R = 12;      /* Rounds */
        RC5_WORD S[26];  /* S Table For Expanded Key */

        RC5_WORD pt[2];
        RC5_WORD iv[2];
	RC5_WORD ak[2];

        LL = 2;  /* LL is number of elements used in L. */

        /* Backwards little edian style baby, owww yeah */

        /* Secret Key */
        L[0] = 0x5ab31114;
        L[1] = 0x00da989a;

        /* Intilization Vector */
        iv[0] = 0xe4e9b2fb;
        iv[1] = 0xbcecd012;

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
	  Preserve the Secret Key
	*/
	ak[0] = L[0];
	ak[1] = L[1];

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
	  Compare to cyphertext.  Do we have a match?
        */
        if(A == 0x561bde39)
        {
                if(B == 0x255c1d3f)
                {
                        return 0;
                }

        }
        printf("Failure\n");
        return 0;
}



int test_attack_56(void)
{
        int i, j, k, LL, T;
        RC5_WORD    L[256/WW];  /* Based on max key size */
        RC5_WORD    A, B;

        int b = 7;       /* Key Length in Bytes */
        int R = 12;      /* Rounds */
        RC5_WORD S[26];  /* S Table For Expanded Key */

        /* I need a file pointer to random */
        FILE *dr;

	RC5_WORD K[2];  /* key storage */
        RC5_WORD pt[2];
        RC5_WORD iv[2];

	int rslt = 0;

        LL = 2;  /* LL is number of elements used in L. */

        /* Backwards little edian style baby, owww yeah */

        /* Secret Key */
        L[0] = 0x00000000;
        L[1] = 0x00000000;

        /* Intilization Vector */
        iv[0] = 0xe4e9b2fb;
        iv[1] = 0xbcecd012;

        /* Plain Text */
        pt[0] = 0x20656854;
        pt[1] = 0x6e6b6e75;

        /* CBC so we Xor */
        pt[0] = pt[0] ^ iv[0];
        pt[1] = pt[1] ^ iv[1];

        printf("CryptNET:  RSA Labs RC5-56 Challenge Full Test Client\n");
        printf("\n");

        T = 26;

        if(NULL == (dr = fopen("/dev/urandom", "r")))
	{
		fprintf(stderr,"Error: Failed to open /dev/urandom device\n");
	}
	else
	{
		rslt = fread(K,2,4,dr);
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
	
	
	/*
	   size K[1]
	*/
	K[1] = K[1]>>8;

        printf("Starting at: 0x%0.8x:0x%0.8x\n", K[0], K[1]);

        while(1) /* crack */
        {
		L[0] = K[0];
		L[1] = K[1];

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
                if(A == 0x561bde39)
                {
                        if(B == 0x255c1d3f)
                        {
                                printf("Secret Key Candidate Found:\t");
                                printf("0x%0.8x:0x%0.8x\n\n", K[0], K[1]);
                                return 0;
                        }
                }

		if(K[0]!=0xffffffff)
		{
                	K[0]++;
		}
                else
                {
                        K[1]++;
                        K[0]=0x00000000;
                }
        }
        return 0;
}


int attack_56(void)
{
        int i, j, k, LL, T;
        RC5_WORD    L[256/WW];  /* Based on max key size */
        RC5_WORD    A, B;

        int b = 7;       /* Key Length in Bytes */
        int R = 12;      /* Rounds */
        RC5_WORD S[26];  /* S Table For Expanded Key */

        /* I need a file pointer to random */
        FILE *dr;

	RC5_WORD K[2];  /* key storage */
        RC5_WORD pt[2];
        RC5_WORD iv[2];

	int rslt = 0;

        LL = 2;  /* LL is number of elements used in L. */

        /* Backwards little edian style baby, owww yeah */

        /* Secret Key */
        L[0] = 0x00000000;
        L[1] = 0x00000000;

        /* Intilization Vector */
        iv[0] = 0x8af0327b;
        iv[1] = 0x8cde17e6;

        /* Plain Text */
        pt[0] = 0x20656854;
        pt[1] = 0x6e6b6e75;

        /* CBC so we Xor */
        pt[0] = pt[0] ^ iv[0];
        pt[1] = pt[1] ^ iv[1];

        printf("CryptNET:  RSA Labs RC5-56 Challenge Full Attack Client\n");
        printf("\n");

        T = 26;

        if(NULL == (dr = fopen("/dev/urandom", "r")))
	{
		fprintf(stderr,"Error: Failed to open /dev/urandom device\n");
	}
	else
	{
		rslt = fread(K,2,4,dr);
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

	/*
	   size K[1]
	*/
	K[1] = K[1]>>8;

        printf("Starting at: 0x%0.8x:0x%0.8x\n", K[0], K[1]);

        while(1) /* crack */
        {
		L[0] = K[0];
		L[1] = K[1];

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
                if(A == 0xa74ed382)
                {
                        if(B == 0x0b8624b3)
                        {
                                printf("Secret Key Candidate Found:\t");
                                printf("0x%0.8x:0x%0.8x\n\n", K[0], K[1]);
                                return 0;
                        }
                }

		if(K[0]!=0xffffffff)
		{
                	K[0]++;
		}
                else
                {
                        K[1]++;
                        K[0]=0x00000000;
                }
        }
        return 0;
}
