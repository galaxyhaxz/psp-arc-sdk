#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "des/des_locl.h"

unsigned char *LoadBinaryFile(char *file, int *bufsize)
{
	unsigned char *p;
	FILE *fp;

	fp = fopen(file, "rb");

	if(fp == NULL) {
		fprintf(stderr, "Can't open file %s\n", file);
		exit(-1);
	}

	fseek(fp, 0L, SEEK_END);
	*bufsize = ftell(fp);
	p = (unsigned char *)malloc(sizeof(unsigned char) * (*bufsize + 1));
	fseek(fp, 0L, SEEK_SET);
	fread(p, sizeof(char), *bufsize, fp);
	fclose(fp);
	return p;
}

#define FILE_ENTRY_SIZE 0x200
#define FILE_BLOCK_SIZE 0x400

// 1.x.x keys
static unsigned char cbc_key [8]={0x86,0x53,0x68,0x4D,0xA8,0x9A,0x56,0x1F};
static unsigned char cbc_iv  [8]={0x41,0xFB,0xCF,0xDD,0xDE,0x9E,0x5B,0x2C};
// 0.6.5 keys
// static unsigned char cbc_key [8]={0xCE,0x5B,0x3C,0x31,0x3C,0x38,0x1D,0x1F};
// static unsigned char cbc_iv  [8]={0x81,0x53,0xAA,0x84,0x55,0x68,0x6C,0xE8};

/* very hacky, but generates identical arc files to Sony's */
void WriteGarbage(FILE *fout, int filesize)
{
	int remain = filesize % FILE_BLOCK_SIZE;
	if(remain == 0) {
		return;
	}

	int diff, padsize, seekback;
	if(filesize >= FILE_BLOCK_SIZE) { // if file can be reused for padding (>= 1kb)
		// pad with bytes from this file
		diff = FILE_BLOCK_SIZE;
		padsize = FILE_BLOCK_SIZE - remain;
		seekback = 0;
	} else {
		// pad with bytes from the previous file
		diff = FILE_BLOCK_SIZE - remain;
		padsize = diff;
		seekback = filesize + FILE_ENTRY_SIZE;
	}

	char garbage[FILE_BLOCK_SIZE];
	fseek(fout, -(seekback + diff), SEEK_CUR);
	fread(garbage, sizeof(char), diff, fout);
	fseek(fout, seekback, SEEK_CUR);
	fwrite(garbage, sizeof(char), padsize, fout);
}

/* cleaner and underflow safe, but not identical to Sony's output */
void WriteZeroes(FILE *fout, int filesize)
{
	int remain = filesize % FILE_BLOCK_SIZE;
	if(remain == 0) {
		return;
	}

	char padding[FILE_BLOCK_SIZE];
	memset(padding, 0, sizeof(padding));

	int padsize = FILE_BLOCK_SIZE - remain;
	fwrite(padding, sizeof(char), padsize, fout);
}

int main(int argc, char *argv[])
{
	int i,j;
	des_key_schedule ks;
	unsigned char file_out[FILE_ENTRY_SIZE];
	unsigned char data_out[FILE_BLOCK_SIZE];

	if(argc != 3) {
		printf("Usage: arcbuild <dir> <arc>\n");
		exit(-1);
	}

	printf("Building Arc\n");

	int filesize;
	char listname[260];
	sprintf(listname, "%s/list.txt", argv[1]);
	unsigned char *pArc = LoadBinaryFile(listname, &filesize);
	unsigned char *p2 = pArc;

	FILE *fout = fopen(argv[2], "w+b");

	while(*p2 != '\0') {
		char fname[FILE_ENTRY_SIZE - 4];
		memset(fname, 0, sizeof(fname));
		char *text = &fname[0];
		while(*p2 != '\n') {
			*text = *p2;
			p2++;
			text++;
		}
		p2++;
		*text = '\0';

		printf("Adding file: %s\n", fname);

		char temp[1024];
		sprintf(temp, "%s/%s", argv[1], fname);
		unsigned char *pFile = LoadBinaryFile(temp, &filesize);
		fwrite(&filesize, sizeof(int), 1, fout);
		fwrite(fname, sizeof(char), sizeof(fname), fout);
		fwrite(pFile, sizeof(char), filesize, fout);
		free(pFile);

		WriteGarbage(fout, filesize);
		//WriteZeroes(fout, filesize);
	}

	fseek(fout, 0L, SEEK_END);
	int bufsize = ftell(fout);
	fseek(fout, 0L, SEEK_SET);
	char *ppp = malloc(bufsize);
	char *ppp2 = ppp;
	fread(ppp, sizeof(char), bufsize, fout);
	fseek(fout, 0L, SEEK_SET);

	printf("Encrypting arc...\n");

	des_set_key_unchecked(&cbc_key,ks);

	memset(file_out, 0, sizeof(file_out));
	memset(data_out, 0, sizeof(data_out));

	j = 0;
	while(j < bufsize) {
		des_cbc_encrypt(ppp2,file_out,FILE_ENTRY_SIZE,ks,cbc_iv,DES_ENCRYPT);
		fwrite(file_out, sizeof(char), FILE_ENTRY_SIZE, fout);

		int csize = *(int *)ppp2;

		int chunks = csize / FILE_BLOCK_SIZE;
		int remain = csize % FILE_BLOCK_SIZE;
		if(remain) {
			chunks++;
		}
		ppp2 += FILE_ENTRY_SIZE;
		j += FILE_ENTRY_SIZE;

		for(i = 0; i < chunks; i++) {
			des_cbc_encrypt(ppp2,data_out,FILE_BLOCK_SIZE,ks,cbc_iv,DES_ENCRYPT);
			fwrite(data_out, sizeof(char), FILE_BLOCK_SIZE, fout);

			ppp2 += FILE_BLOCK_SIZE;
			j += FILE_BLOCK_SIZE;
		}
	}

	fclose(fout);
	free(pArc);
	free(ppp);

	printf("Finished!\n");
}
