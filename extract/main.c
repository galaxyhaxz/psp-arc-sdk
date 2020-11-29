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

int main(int argc, char *argv[])
{
	int i,j;
	des_key_schedule ks;
	unsigned char file_out[FILE_ENTRY_SIZE];
	unsigned char data_out[FILE_BLOCK_SIZE];

	if(argc != 2) {
		printf("Usage: arcdump <arc>\n");
		exit(-1);
	}

	printf("Decrypting Arc\n");

	int filesize;
	unsigned char *pArc = LoadBinaryFile(argv[1], &filesize);
	unsigned char *p2 = pArc;

	des_set_key_unchecked(&cbc_key,ks);

	memset(file_out, 0, sizeof(file_out));
	memset(data_out, 0, sizeof(data_out));

	mkdir("psp_arc");
	mkdir("psp_arc/kd");
	mkdir("psp_arc/kd/resource");
	mkdir("psp_arc/vsh");
	mkdir("psp_arc/vsh/module");
	mkdir("psp_arc/vsh/resource");
	mkdir("psp_arc/vsh/etc");
	mkdir("psp_arc/font");
	mkdir("psp_arc/data");
	mkdir("psp_arc/data/cert");
	mkdir("psp_arc/dic");

	char list_name[] = "psp_arc/list.txt";

	FILE *fp = fopen(list_name, "wb");

	if(fp == NULL) {
		fprintf(stderr, "Can't create file %s\n", list_name);
		exit(-1);
	}

	j = 0;
	while(j < filesize) {
		des_cbc_encrypt(p2,file_out,FILE_ENTRY_SIZE,ks,cbc_iv,DES_DECRYPT);

		char *file_name = &file_out[4];
		char name_buff[508];
		sprintf(name_buff, "psp_arc/%s", file_name);

		fprintf(fp, "%s\r\n", file_name);
		//fwrite(file_out, sizeof(char), FILE_ENTRY_SIZE, fp);

		int csize = *(int *)file_out;
		printf("Writing: `%s` (%d bytes)\n", file_name, csize);
		// putchar('#'); // Sony's descriptive progress bar

		int chunks = csize / FILE_BLOCK_SIZE;
		int remain = csize % FILE_BLOCK_SIZE;
		if(remain) {
			chunks++;
		}
		p2 += FILE_ENTRY_SIZE;
		j += FILE_ENTRY_SIZE;

		FILE *pFile = fopen(name_buff, "wb");

		if(pFile == NULL) {
			fprintf(stderr, "Can't create file %s\n", name_buff);
			exit(-1);
		}

		for(i = 0; i < chunks; i++) {
			des_cbc_encrypt(p2,data_out,FILE_BLOCK_SIZE,ks,cbc_iv,DES_DECRYPT);

			int wsize = FILE_BLOCK_SIZE;
			if(csize < wsize) {
				wsize = csize;
			}
			fwrite(data_out, sizeof(char), wsize, pFile);

			p2 += FILE_BLOCK_SIZE;
			j += FILE_BLOCK_SIZE;
			csize -= FILE_BLOCK_SIZE;
		}

		fclose(pFile);
	}

	fclose(fp);
	free(pArc);

	printf("Finished!\n");
}
