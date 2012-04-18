/*  2000.09.01     */
/*  CryptNET       */
/*  vab@dublin.ie  */

/*  This source code is derived from rfc2040   */
/*  Basically it is the code in rfc2040 with   */
/*  some intialized variables, a lot of the    */
/*  code that wasn't necessary for working     */
/*  with 64bits on 32bit archs cut out so you  */
/*  can clearly see what's going on, all the   */
/*  decryption code pulled out and a set of    */
/*  compares stuck in where you would normally */ 
/*  return processed bits. - VAB               */ 

#include <stdio.h>

/* Definitions for RC5 as a 64 bit block cipher. */
/* The "unsigned int" will be 32 bits on all but */
/* the oldest compilers, which will make it 16 bits. */
/* On a DEC Alpha "unsigned long" is 64 bits, not 32. */
#define RC5_WORD     unsigned int
#define W            (32)
#define WW           (W / 8) /* = 4 */
#define ROT_MASK     (W - 1) /* 31 */
#define BB           ((2 * W) / 8) /* Bytes per block */

/* Define macros used in multiple procedures. */
/* These macros assumes ">>" is an unsigned operation, */
/* and that x and s are of type RC5_WORD. */
#define SHL(x,s)    ((RC5_WORD)((x)<<((s)&ROT_MASK)))
#define SHR(x,s,w)  ((RC5_WORD)((x)>>((w)-((s)&ROT_MASK))))
#define ROTL(x,s,w) ((RC5_WORD)(SHL((x),(s))|SHR((x),(s),(w))))

/* We're working on 32bits archs here */
#define Pw   0xb7e15163
#define Qw   0x9e3779b9
