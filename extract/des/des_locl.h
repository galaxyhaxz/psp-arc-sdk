#define DES_LONG unsigned long

typedef unsigned char des_cblock[8];
typedef /* const */ unsigned char const_des_cblock[8];
/* With "const", gcc 2.8.1 on Solaris thinks that des_cblock *
 * and const_des_cblock * are incompatible pointer types. */

typedef struct des_ks_struct
{
	union	{
		des_cblock cblock;
		/* make sure things are correct size on machines with
		 * 8 byte longs */
		DES_LONG deslong[2];
		} ks;
	int weak_key;
} des_key_schedule[16];

#define DES_KEY_SZ 	(sizeof(des_cblock))
#define DES_SCHEDULE_SZ (sizeof(des_key_schedule))

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#define ITERATIONS 16

#if defined(WIN32) && defined(_MSC_VER)
#define	ROTATE(a,n)	(_lrotr(a,n))
#else
#define	ROTATE(a,n)	(((a)>>(n))+((a)<<(32-(n))))
#endif

#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
	(b)^=(t),\
	(a)^=((t)<<(n)))

#define IP(l,r) \
	{ \
	register DES_LONG tt; \
	PERM_OP(r,l,tt, 4,0x0f0f0f0fL); \
	PERM_OP(l,r,tt,16,0x0000ffffL); \
	PERM_OP(r,l,tt, 2,0x33333333L); \
	PERM_OP(l,r,tt, 8,0x00ff00ffL); \
	PERM_OP(r,l,tt, 1,0x55555555L); \
	}

#define FP(l,r) \
	{ \
	register DES_LONG tt; \
	PERM_OP(l,r,tt, 1,0x55555555L); \
	PERM_OP(r,l,tt, 8,0x00ff00ffL); \
	PERM_OP(l,r,tt, 2,0x33333333L); \
	PERM_OP(r,l,tt,16,0x0000ffffL); \
	PERM_OP(l,r,tt, 4,0x0f0f0f0fL); \
	}

#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
	u=R^s[S  ]; \
	t=R^s[S+1]

#define D_ENCRYPT(LL,R,S) {\
	unsigned int u1,u2,u3; \
	LOAD_DATA(R,S,u,t,E0,E1,u1); \
	u>>=2L; \
	t=ROTATE(t,6); \
	u2=(int)u>>8L; \
	u1=(int)u&0x3f; \
	u2&=0x3f; \
	u>>=16L; \
	LL^=des_SPtrans[0][u1]; \
	LL^=des_SPtrans[2][u2]; \
	u3=(int)u>>8L; \
	u1=(int)u&0x3f; \
	u3&=0x3f; \
	LL^=des_SPtrans[4][u1]; \
	LL^=des_SPtrans[6][u3]; \
	u2=(int)t>>8L; \
	u1=(int)t&0x3f; \
	u2&=0x3f; \
	t>>=16L; \
	LL^=des_SPtrans[1][u1]; \
	LL^=des_SPtrans[3][u2]; \
	u3=(int)t>>8L; \
	u1=(int)t&0x3f; \
	u3&=0x3f; \
	LL^=des_SPtrans[5][u1]; \
	LL^=des_SPtrans[7][u3]; }

#define c2l(c,l)	(l =((DES_LONG)(*((c)++)))    , \
			 l|=((DES_LONG)(*((c)++)))<< 8L, \
			 l|=((DES_LONG)(*((c)++)))<<16L, \
			 l|=((DES_LONG)(*((c)++)))<<24L)

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24L)&0xff))

#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((DES_LONG)(*(--(c))))<<24L; \
			case 7: l2|=((DES_LONG)(*(--(c))))<<16L; \
			case 6: l2|=((DES_LONG)(*(--(c))))<< 8L; \
			case 5: l2|=((DES_LONG)(*(--(c))));     \
			case 4: l1 =((DES_LONG)(*(--(c))))<<24L; \
			case 3: l1|=((DES_LONG)(*(--(c))))<<16L; \
			case 2: l1|=((DES_LONG)(*(--(c))))<< 8L; \
			case 1: l1|=((DES_LONG)(*(--(c))));     \
				} \
			}

#define l2cn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)>>24L)&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>>16L)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>> 8L)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)     )&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)>>24L)&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>>16L)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>> 8L)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)     )&0xff); \
				} \
			}

extern void des_encrypt1(DES_LONG *data, des_key_schedule ks, int enc);
extern void des_set_key_unchecked(const_des_cblock *key, des_key_schedule schedule);
extern void des_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
	     des_key_schedule schedule, unsigned char *iv, int enc);
