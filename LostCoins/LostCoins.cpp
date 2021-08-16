#include "LostCoins.h"
#include "Base58.h"
#include "Bech32.h"

#include "hash/sha512.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>

#include <string>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha256.cpp"
#include <sstream>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>

#include <stdio.h>
#include <vector>
#include <random>
#include <ctime>
#include <iomanip>
using namespace std;

#ifndef WIN64
#include <pthread.h>
#endif

using namespace std;

Point Gn[CPU_GRP_SIZE / 2];
Point _2Gn;

// ----------------------------------------------------------------------------

LostCoins::LostCoins(string addressFile, string seed, string zez, int diz, int searchMode,
	bool useGpu, string outputFile, bool useSSE, uint32_t maxFound,
	uint64_t rekey, int nbit, bool paranoiacSeed, const std::string& rangeStart1, const std::string& rangeEnd1, bool& should_exit)
{
	this->searchMode = searchMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->addressFile = addressFile;
	this->rekey = rekey;
	this->nbit = nbit;
	this->maxFound = maxFound;
	this->seed = seed;
	this->zez = zez;
	this->diz = diz;
	this->searchType = P2PKH;

	secp = new Secp256K1();
	secp->Init();

	// load address file
	uint8_t buf[20];
	FILE* wfd;
	uint64_t N = 0;

	wfd = fopen(this->addressFile.c_str(), "rb");
	if (!wfd) {
		printf("%s can not open\n", this->addressFile.c_str());
		exit(1);
	}

	_fseeki64(wfd, 0, SEEK_END);
	N = _ftelli64(wfd);
	N = N / 20;
	rewind(wfd);

	DATA = (uint8_t*)malloc(N * 20);
	memset(DATA, 0, N * 20);

	bloom = new Bloom(2 * N, 0.000001);

	uint64_t percent = (N - 1) / 100;
	uint64_t i = 0;
	printf("\n");
	while (i < N && !should_exit) {
		memset(buf, 0, 20);
		memset(DATA + (i * 20), 0, 20);
		if (fread(buf, 1, 20, wfd) == 20) {
			bloom->add(buf, 20);
			memcpy(DATA + (i * 20), buf, 20);
			if (i % percent == 0) {
				printf("\rLoading       : %llu %%", (i / percent));
				fflush(stdout);
			}
		}
		i++;
	}
	printf("\n");
	fclose(wfd);

	if (should_exit) {
		delete secp;
		delete bloom;
		if (DATA)
			free(DATA);
		exit(0);
	}

	BLOOM_N = bloom->get_bytes();
	TOTAL_ADDR = N;
	printf("Loaded        : %s address\n", formatThousands(i).c_str());
	printf("\n");

	bloom->print();
	printf("\n");

	lastRekey = 0;

	// Compute Generator table G[n] = (n+1)*G

	Point g = secp->G;
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g, secp->G);
		Gn[i] = g;
	}
	// _2Gn = CPU_GRP_SIZE*G
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

	// Constant for endomorphism
	// if a is a nth primitive root of unity, a^-1 is also a nth primitive root.
	// beta^3 = 1 mod p implies also beta^2 = beta^-1 mop (by multiplying both side by beta^-1)
	// (beta^3 = 1 mod p),  beta2 = beta^-1 = beta^2
	// (lambda^3 = 1 mod n), lamba2 = lamba^-1 = lamba^2
	beta.SetBase16("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");
	lambda.SetBase16("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
	beta2.SetBase16("851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40");
	lambda2.SetBase16("ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283ce");
	

	if (this->nbit <= 0) {
		string salt = "LostCoins";
		unsigned char hseed[64];
		pbkdf2_hmac_sha512(hseed, 64, (const uint8_t*)seed.c_str(), seed.length(),
			(const uint8_t*)salt.c_str(), salt.length(),
			2048);
		startKey.SetInt32(0);
		//sha256(hseed, 64, (unsigned char*)startKey.bits64);
	}
	else {
		startKey.Rand(this->nbit);
	}
	
	char *ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	printf("  Start Time  : %s", ctimeBuff);
	
	
	
	if (rekey == 0) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 26 letters \n  List        : abcdefghijklmnopqrstuvwxyz \n  Rotor       : Generation of 3-9 random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str());
	}
	if (rekey == 1) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Mode        : Generating random hashes -r 1 (Rotor-Cuda Power) \n  Reload      : Every 1 hex  \n  How work R1 : GPU cores generate hashes into a buffer (~500Mk) \n  How work R1 : After they are sent to the device for checking with a bloom filter to find a positive bitcoin address \n  Range bit   : %.0f(bit) recommended -n 256 (256 searches in the 256-252 range and below) \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, (double)nbit);

	}
	if (rekey == 2) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Mode        : Generating random hashes + values.  (Speed Rotor-Cuda Power) \n  Reload      : Every 50.000.000.000 hex and by the total counter \n  Range bit   : %.0f(bit) recommended -n 256 (256 searches in the 256-252 range and below)  \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, (double)nbit);

	}
	if (rekey == 3) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Mode        : Generating random hashes. (Speed Rotor-Cuda Power) \n  Reload      : Every 100.000.000.000 hex and by the total counter \n  Range bit   : %.0f(bit) recommended -n 256 (256 searches in the 256-252 range and below) \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, (double)nbit);

	}
	if (rekey == 4) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 10 digits  \n  List        : 0123456789 \n  Rotor       : Generation of %.0f random digits \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 5) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 26 letters \n  List        : abcdefghijklmnopqrstuvwxyz \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 6) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 26 letters \n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 7) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 36 symbols \n  List        : abcdefghijklmnopqrstuvwxyz0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 8) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 36 symbols \n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 9) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 52 letters \n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 10) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 62 letters \n  List        : abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 11) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 93 symbols \n  List        : abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 12) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 33 letters (russian) \n  List        : абвгдеЄжзийклмнопрстуфхцчшщъыьэю€ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 13) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 33 letters (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 14) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 66 letters (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 15) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 76 symbols (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 16) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 107 symbols (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 17) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random digits] \n  Using       : 10 digits \n  List        : 0123456789 \n  Rotor       : Generation of %.0f random digits \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 18) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 26 letters \n  List        : abcdefghijklmnopqrstuvwxyz \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 19) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 26 letters \n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 20) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 36 symbols \n  List        : abcdefghijklmnopqrstuvwxyz0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 21) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 36 symbols \n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 22) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 52 letters \n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 23) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 62 letters \n  List        : abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 24) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 92 symbols \n  List        : abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 25) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 33 letters (russian) \n  List        : абвгдеЄжзийклмнопрстуфхцчшщъыьэю€ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 26) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 33 letters (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 27) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 66 letters (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 28) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 76 symbols (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n   Donate     : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 29) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s+[random letters] \n  Using       : 106 symbols (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 30) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 10 digits \n  List        : 0123456789 \n  Rotor       : Generation of %.0f random digits \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 31) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 26 letters \n  List        : abcdefghijklmnopqrstuvwxyz \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 32) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 26 letters \n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 33) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 36 symbols \n  List        : abcdefghijklmnopqrstuvwxyz0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 34) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 36 symbols \n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 35) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 52 letters \n  List        : ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 36) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 62 letters \n  List        : abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 37) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 93 symbols \n  List        : abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 38) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 33 letters (russian) \n  List        : абвгдеЄжзийклмнопрстуфхцчшщъыьэю€ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 39) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 33 letters (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 40) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 66 letters (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 41) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 76 symbols (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789 \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate     : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 42) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(space)[random letters] \n  Using       : 107 symbols (russian) \n  List        : јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~ \n  Rotor       : Generation of %.0f random letters \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 43) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s [not supported] \n  Using       : L(llllllll)dd \n  Rotor       : Generation customizable %.0f random letters l \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 44) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s [not supported] \n  Using       : L(llllllll)dddd \n  Rotor       : Generation customizable %.0f random letters l \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 45) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s [not supported] \n  Using       : L(llllllll)dddddd \n  Rotor       : Generation customizable %.0f random letters l \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}
	if (rekey == 46) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s [not supported] \n  Using       : 2 words (3-9 size) \n  Rotor       : Generation random 2 words from letters l (3-9) \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str());
	}
	if (rekey == 47) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s \n  Using       : Passphrase + 2 word (3-9 size) \n  Rotor       : Generation random 2 words from letters l (3-9) \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str());
	}
	if (rekey == 48) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s [not supported] \n  Using       : Mnemonic 12 words (3-5 size) \n  Rotor       : Generation random 12 words from letters l (size 3-5) \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str());
	}
	if (rekey == 49) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s [not supported] \n  Using       : Mnemonic 12 words (3-7 size) \n  Rotor       : Generation random 12 words from letters l (size 3-7) \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str());
	}
	if (rekey == 50) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s [not supported] \n  Using       : Mnemonic 12 words (3-10 size) \n  Rotor       : Generation random 12 words from letters l (size 3-10) \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str());
	}
	if (rekey == 51) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s [not supported] \n  Using       : Mnemonic 12 words 3-12 (size) \n  Rotor       : Generation random 12 words from letters l (size 3-12) \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str());
	}

	if (rekey == 52) {

		printf("\n  Random mode : %.0f \n  Random      : Finding a puzzle in a ranges", (double)rekey);
		
		if (nbit == 1) {
			string tup = "0";
			string tup2 = "f";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 2) {
			string tup = "01";
			string tup2 = "ff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 3) {
			string tup = "001";
			string tup2 = "fff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 4) {
			string tup = "0001";
			string tup2 = "ffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 5) {
			string tup = "00001";
			string tup2 = "fffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 6) {
			string tup = "000001";
			string tup2 = "ffffff";

			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 7) {
			string tup = "0000001";
			string tup2 = "fffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 8) {
			string tup = "00000001";
			string tup2 = "ffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 9) {
			string tup = "000000001";
			string tup2 = "fffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 10) {
			string tup = "0000000001";
			string tup2 = "ffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 11) {
			string tup = "00000000001";
			string tup2 = "fffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 12) {
			string tup = "000000000001";
			string tup2 = "ffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 13) {
			string tup = "0000000000001";
			string tup2 = "fffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 14) {
			string tup = "00000000000001";
			string tup2 = "ffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 15) {
			string tup = "000000000000001";
			string tup2 = "fffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 16) {
			string tup = "000000000000001";
			string tup2 = "fffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 17) {
			string tup = "00000000000000001";
			string tup2 = "fffffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 18) {
			string tup = "000000000000000001";
			string tup2 = "ffffffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 19) {
			string tup = "0000000000000000001";
			string tup2 = "fffffffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 20) {
			string tup = "00000000000000000001";
			string tup2 = "ffffffffffffffffffff";
			
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 21) {
			string tup = "000000000000000000001";
			string tup2 = "fffffffffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 22) {
			string tup = "0000000000000000000001";
			string tup2 = "ffffffffffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 23) {
			string tup = "00000000000000000000001";
			string tup2 = "fffffffffffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 24) {
			string tup = "000000000000000000000001";
			string tup2 = "ffffffffffffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit == 25) {
			string tup = "0000000000000000000000001";
			string tup2 = "fffffffffffffffffffffffff";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		if (nbit > 25) {
			string tup = "000000000000000000000000001...";
			string tup2 = "fffffffffffffffffffffffffff...";
			std::stringstream ss1;
			ss1 << seed << tup;
			std::string input8 = ss1.str();

			char* gyg1 = &input8[0];
			Int st1;
			st1.SetBase10(gyg1);

			std::stringstream ss2;
			ss2 << seed << tup2;
			std::string input9 = ss2.str();

			char* fun2 = &input9[0];
			Int fin2;
			fin2.SetBase10(fun2);
			printf("\n  Start       : (%d bit) %s (number: %s) \n  Finish      : (%d bit) %s (number: %s) \n  Range       : random %.0fx(0-f) %s-%s \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", st1.GetBitLength(), input8.c_str(), st1.GetBase10().c_str(), fin2.GetBitLength(), input9.c_str(), fin2.GetBase10().c_str(), (double)nbit, tup.c_str(), tup2.c_str());
		}
		
	}
	if (rekey == 53) {

		printf("\n  Random mode : %.0f \n  Random      : Finding in a range \n", (double)rekey);
		printf("  Use range   : %d bits\n", nbit);
		printf("  Rotor       : If use -n 0  will random generate in the whole range 1-256 (bit)\n");
		printf("  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}


	if (rekey == 54) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Mode        : %.0f Very very slow algaritm (For one CPU core only!!! -t 1, in GPU work 1 core)\n  Passphrase  : Starting word %s to continue... \n  Using       : Passphrase -> Passphrasf -> Paszzzzzzz - ZZZZZZZZZZZ (Uld) \n  Rotor       : Sequential continuation of generation  \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str());
	}
	if (rekey == 55) {
		setlocale(LC_ALL, "Russian");
		printf("\n  Random mode : %.0f \n  Passphrase  : %s(not supported) \n  Using       : 31 symbols  \n  List        : !#$%&'()*+,-./:;<=>?@[\]^_`{|}~ \n  Rotor       : Generation of %.0f random symbols \n  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n", (double)rekey, seed.c_str(), (double)nbit);
	}

	if (rekey == 56) {

		char* gyg = &seed[0];
			char* fun = &zez[0];

			this->rangeStart1.SetBase16(gyg);
			this->rangeEnd1.SetBase16(fun);

			this->rangeDiff2.Set(&this->rangeEnd1);
			this->rangeDiff2.Sub(&this->rangeStart1);
			this->rangeDiff3.Set(&this->rangeEnd1);

			int gaz2 = (int)rangeDiff2.GetBase10().c_str();

		printf("\n  Random mode : %.0f \n  Random      : Finding in a ranges \n", (double)rekey);
		printf("  Global start: %s (%d bit)\n", this->rangeStart1.GetBase16().c_str(), this->rangeStart1.GetBitLength());
		printf("  Global end  : %s (%d bit)\n", this->rangeEnd1.GetBase16().c_str(), this->rangeEnd1.GetBitLength());
		printf("  Global range: %s (%d bit)\n", this->rangeDiff2.GetBase16().c_str(), this->rangeDiff2.GetBitLength());
		printf("  Site        : https://github.com/phrutis/LostCoins \n  Donate      : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9 \n\n");
	}



	if (rekey > 56) {
		printf("\n  ERROR!!! \n  Check -r ? \n  Range -r from 0 - 56\n  BYE   \n\n");
		exit(-1);

	}


}

LostCoins::~LostCoins()
{
	delete secp;
	delete bloom;
	if (DATA)
		free(DATA);
}

// ----------------------------------------------------------------------------

double log1(double x)
{
	// Use taylor series to approximate log(1-x)
	return -x - (x * x) / 2.0 - (x * x * x) / 3.0 - (x * x * x * x) / 4.0;
}

void LostCoins::output(string addr, string pAddr, string pAddrHex)
{

#ifdef WIN64
	WaitForSingleObject(ghMutex, INFINITE);
#else
	pthread_mutex_lock(&ghMutex);
#endif

	FILE *f = stdout;
	bool needToClose = false;

	if (outputFile.length() > 0) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("Cannot open %s for writing\n", outputFile.c_str());
			f = stdout;
		}
		else {
			needToClose = true;
		}
	}

	if (!needToClose)
		printf("\n");

	fprintf(f, "PubAddress: %s\n", addr.c_str());

	//if (startPubKeySpecified) {

	//	fprintf(f, "PartialPriv: %s\n", pAddr.c_str());

	//}
	//else
	{


		switch (searchType) {
		case P2PKH:
			fprintf(f, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
			break;
		case P2SH:
			fprintf(f, "Priv (WIF): p2wpkh-p2sh:%s\n", pAddr.c_str());
			break;
		case BECH32:
			fprintf(f, "Priv (WIF): p2wpkh:%s\n", pAddr.c_str());
			break;
		}
		fprintf(f, "Priv (HEX): 0x%s\n", pAddrHex.c_str());

	}
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	printf("\n\n=================================================================================\n* PubAddress: %s \n* Priv (WIF): p2pkh: %s \n* Priv (HEX): %s \n=================================================================================\n\n", addr.c_str(), pAddr.c_str(), pAddrHex.c_str());
	if (needToClose)
		fclose(f);

#ifdef WIN64
	ReleaseMutex(ghMutex);
#else
	pthread_mutex_unlock(&ghMutex);
#endif

}

// ----------------------------------------------------------------------------

bool LostCoins::checkPrivKey(string addr, Int &key, int32_t incr, int endomorphism, bool mode)
{

	Int k(&key);
	//Point sp = startPubKey;

	if (incr < 0) {
		k.Add((uint64_t)(-incr));
		k.Neg();
		k.Add(&secp->order);
		//if (startPubKeySpecified)
		//	sp.y.ModNeg();
	}
	else {
		k.Add((uint64_t)incr);
	}

	// Endomorphisms
	switch (endomorphism) {
	case 1:
		k.ModMulK1order(&lambda);
		//if (startPubKeySpecified)
		//	sp.x.ModMulK1(&beta);
		break;
	case 2:
		k.ModMulK1order(&lambda2);
		//if (startPubKeySpecified)
		//	sp.x.ModMulK1(&beta2);
		break;
	}

	// Check addresses
	Point p = secp->ComputePublicKey(&k);
	//if (startPubKeySpecified)
	//	p = secp->AddDirect(p, sp);

	string chkAddr = secp->GetAddress(searchType, mode, p);
	if (chkAddr != addr) {

		//Key may be the opposite one (negative zero or compressed key)
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		//if (startPubKeySpecified) {
		//	sp.y.ModNeg();
		//	p = secp->AddDirect(p, sp);
		//}
		string chkAddr = secp->GetAddress(searchType, mode, p);
		if (chkAddr != addr) {
			printf("\nWarning, wrong private key generated !\n");
			printf("  Addr :%s\n", addr.c_str());
			printf("  Check:%s\n", chkAddr.c_str());
			printf("  Endo:%d incr:%d comp:%d\n", endomorphism, incr, mode);
			//return false;
		}

	}

	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16());

	return true;

}

// ----------------------------------------------------------------------------

#ifdef WIN64
DWORD WINAPI _FindKey(LPVOID lpParam)
{
#else
void *_FindKey(void *lpParam)
{
#endif
	TH_PARAM *p = (TH_PARAM *)lpParam;
	p->obj->FindKeyCPU(p);
	return 0;
}

#ifdef WIN64
DWORD WINAPI _FindKeyGPU(LPVOID lpParam)
{
#else
void *_FindKeyGPU(void *lpParam)
{
#endif
	TH_PARAM *p = (TH_PARAM *)lpParam;
	p->obj->FindKeyGPU(p);
	return 0;
}

// ----------------------------------------------------------------------------

void LostCoins::checkAddresses(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[20];
	Point pte1[1];
	Point pte2[1];

	// Point
	secp->GetHash160(searchType, compressed, p1, h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i, 0, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #1
	pte1[0].x.ModMulK1(&p1.x, &beta);
	pte1[0].y.Set(&p1.y);
	secp->GetHash160(searchType, compressed, pte1[0], h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i, 1, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #2
	pte2[0].x.ModMulK1(&p1.x, &beta2);
	pte2[0].y.Set(&p1.y);
	secp->GetHash160(searchType, compressed, pte2[0], h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i, 2, compressed)) {
			nbFoundKey++;
		}
	}

	// Curve symetrie
	// if (x,y) = k*G, then (x, -y) is -k*G
	p1.y.ModNeg();
	secp->GetHash160(searchType, compressed, p1, h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -i, 0, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #1
	pte1[0].y.ModNeg();
	secp->GetHash160(searchType, compressed, pte1[0], h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -i, 1, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #2
	pte2[0].y.ModNeg();
	secp->GetHash160(searchType, compressed, pte2[0], h0);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -i, 2, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void LostCoins::checkAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4)
{
	unsigned char h0[20];
	unsigned char h1[20];
	unsigned char h2[20];
	unsigned char h3[20];
	Point pte1[4];
	Point pte2[4];

	// Point -------------------------------------------------------------------------
	secp->GetHash160(searchType, compressed, p1, p2, p3, p4, h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i + 0, 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, i + 1, 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, i + 2, 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, i + 3, 0, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #1
	// if (x, y) = k * G, then (beta*x, y) = lambda*k*G
	pte1[0].x.ModMulK1(&p1.x, &beta);
	pte1[0].y.Set(&p1.y);
	pte1[1].x.ModMulK1(&p2.x, &beta);
	pte1[1].y.Set(&p2.y);
	pte1[2].x.ModMulK1(&p3.x, &beta);
	pte1[2].y.Set(&p3.y);
	pte1[3].x.ModMulK1(&p4.x, &beta);
	pte1[3].y.Set(&p4.y);

	secp->GetHash160(searchType, compressed, pte1[0], pte1[1], pte1[2], pte1[3], h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i + 0, 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, i + 1, 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, i + 2, 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, i + 3, 1, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #2
	// if (x, y) = k * G, then (beta2*x, y) = lambda2*k*G
	pte2[0].x.ModMulK1(&p1.x, &beta2);
	pte2[0].y.Set(&p1.y);
	pte2[1].x.ModMulK1(&p2.x, &beta2);
	pte2[1].y.Set(&p2.y);
	pte2[2].x.ModMulK1(&p3.x, &beta2);
	pte2[2].y.Set(&p3.y);
	pte2[3].x.ModMulK1(&p4.x, &beta2);
	pte2[3].y.Set(&p4.y);

	secp->GetHash160(searchType, compressed, pte2[0], pte2[1], pte2[2], pte2[3], h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, i + 0, 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, i + 1, 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, i + 2, 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, i + 3, 2, compressed)) {
			nbFoundKey++;
		}
	}

	// Curve symetrie -------------------------------------------------------------------------
	// if (x,y) = k*G, then (x, -y) is -k*G

	p1.y.ModNeg();
	p2.y.ModNeg();
	p3.y.ModNeg();
	p4.y.ModNeg();

	secp->GetHash160(searchType, compressed, p1, p2, p3, p4, h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -(i + 0), 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, -(i + 1), 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, -(i + 2), 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, -(i + 3), 0, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #1
	// if (x, y) = k * G, then (beta*x, y) = lambda*k*G
	pte1[0].y.ModNeg();
	pte1[1].y.ModNeg();
	pte1[2].y.ModNeg();
	pte1[3].y.ModNeg();

	secp->GetHash160(searchType, compressed, pte1[0], pte1[1], pte1[2], pte1[3], h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -(i + 0), 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, -(i + 1), 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, -(i + 2), 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, -(i + 3), 1, compressed)) {
			nbFoundKey++;
		}
	}

	// Endomorphism #2
	// if (x, y) = k * G, then (beta2*x, y) = lambda2*k*G
	pte2[0].y.ModNeg();
	pte2[1].y.ModNeg();
	pte2[2].y.ModNeg();
	pte2[3].y.ModNeg();

	secp->GetHash160(searchType, compressed, pte2[0], pte2[1], pte2[2], pte2[3], h0, h1, h2, h3);
	if (CheckBloomBinary(h0) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h0);
		if (checkPrivKey(addr, key, -(i + 0), 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h1);
		if (checkPrivKey(addr, key, -(i + 1), 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h2);
		if (checkPrivKey(addr, key, -(i + 2), 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3) > 0) {
		string addr = secp->GetAddress(searchType, compressed, h3);
		if (checkPrivKey(addr, key, -(i + 3), 2, compressed)) {
			nbFoundKey++;
		}
	}
}


static string const digits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";


string increment(string value) {
	string result;
	bool carry = true;
	for (int i = value.size() - 1; i >= 0; --i) {
		int v = digits.find(value.at(i));
		v += carry;
		carry = v >= digits.size();
		v = carry ? 0 : v;
		result.push_back(digits.at(v));
	}
	reverse(begin(result), end(result));
	return result;
}

bool compare_digits(char a, char b) {
	int va = digits.find(a);
	int vb = digits.find(b);
	return va < vb;
}

bool compare(string const& a, string const& b) {
	return lexicographical_compare(begin(a), end(a), begin(b), end(b), compare_digits);
}



const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
enum { base = sizeof(alphabet) - 1, length = 8 };
char number[length + 1];

void print_digits(int pos)
{
	if (length == pos) {
		puts(number);
	}
	else {
		int i = 0;
		for (; i < base; ++i) {
			number[pos] = alphabet[i];
			print_digits(pos + 1);
		}
	}
}

// ----------------------------------------------------------------------------
void LostCoins::getCPUStartingKey(int thId, Int &key, Point &startP)
{

	if (rekey == 0) {

		int N = 3 + rand() % 7;
		char str[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);

		if (diz == 0) {
			printf("\r [%s]", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s]", pass, key.GetBase16().c_str());
		}
	}
	if (rekey == 1) {
		key.Rand(nbit);
		if (diz == 0) {
			printf("\r (%d bit) ", key.GetBitLength());
		}
		if (diz == 1) {
			printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
		}
	}
	if (rekey == 2) {
		key.Rand(nbit);
		if (diz == 0) {
			printf("\r (%d bit) ", key.GetBitLength());
		}
		if (diz == 1) {
			printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
		}
	}
	if (rekey == 3) {
		key.Rand(nbit);
		if (diz == 0) {
			printf("\r (%d bit) ", key.GetBitLength());
		}
		if (diz == 1) {
			printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
		}
	}
	if (rekey == 4) {
		int N = nbit;
		char str[]{ "0123456789" };
		int strN = 10; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 5) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 6) {
		int N = nbit;
		char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 7) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyz0123456789" };
		int strN = 36; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 8) {
		int N = nbit;
		char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
		int strN = 36; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 9) {
		int N = nbit;
		char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };
		int strN = 52; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 10) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
		int strN = 62; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 11) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
		int strN = 93; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 12) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "абвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
		int strN = 33; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 13) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя" };
		int strN = 33; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 14) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
		int strN = 66; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 15) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789" };
		int strN = 76; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 16) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
		int strN = 107; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}
	if (rekey == 17) {
		int N = nbit;
		char str[]{ "0123456789" };
		int strN = 10; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 18) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 19) {
		int N = nbit;
		char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 20) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyz0123456789" };
		int strN = 36; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 21) {
		int N = nbit;
		char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
		int strN = 36; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 22) {
		int N = nbit;
		char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };
		int strN = 52; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 23) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
		int strN = 62; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 24) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
		int strN = 92; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 25) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "абвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
		int strN = 33; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 26) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя" };
		int strN = 33; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 27) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
		int strN = 66; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 28) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789" };
		int strN = 76; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 29) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
		int strN = 106; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 30) {
		int N = nbit;
		char str[]{ "0123456789" };
		int strN = 10; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 31) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 32) {
		int N = nbit;
		char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 33) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyz0123456789" };
		int strN = 36; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 34) {
		int N = nbit;
		char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
		int strN = 36; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 35) {
		int N = nbit;
		char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };
		int strN = 52; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 36) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
		int strN = 62; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 37) {
		int N = nbit;
		char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
		int strN = 93; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 38) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "абвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
		int strN = 33; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 39) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя" };
		int strN = 33; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 40) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
		int strN = 66; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 41) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789" };
		int strN = 76; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 42) {
		setlocale(LC_ALL, "Russian");
		int N = nbit;
		char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
		int strN = 107; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		std::stringstream ss;
		ss << seed << " " << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}
	}

	if (rekey == 43) {
		int N = 2;
		char str[]{ "0123456789" };
		int strN = 10; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		int N2 = nbit;
		char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN2 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки

		int N3 = 1;
		char str3[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
		int strN3 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N3; i++)
		{
			pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
		}
		pass3[N3] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << pass3 << pass2 << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 44) {
		int N = 4;
		char str[]{ "0123456789" };
		int strN = 10; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		int N2 = nbit;
		char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN2 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки

		int N3 = 1;
		char str3[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
		int strN3 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N3; i++)
		{
			pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
		}
		pass3[N3] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << pass3 << pass2 << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 45) {
		int N = 6;
		char str[]{ "0123456789" };
		int strN = 10; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		int N2 = nbit;
		char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN2 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки

		int N3 = 1;
		char str3[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
		int strN3 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N3; i++)
		{
			pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
		}
		pass3[N3] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << pass3 << pass2 << pass;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}

	if (rekey == 46) {
		int N2 = 3 + rand() % 6;
		char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN2 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки

		int N4 = 3 + rand() % 6;
		char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN4 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N4; i++)
		{
			pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
		}
		pass4[N4] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << pass2 << " " << pass4;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 47) {
		int N2 = 3 + rand() % 6;
		char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN2 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки
		int N4 = 3 + rand() % 6;
		char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN4 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N4; i++)
		{
			pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
		}
		pass4[N4] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << seed << " " << pass2 << " " << pass4;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}

	if (rekey == 48) {
		int N = 3 + rand() % 3;
		char str[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		int N1 = 3 + rand() % 3;
		char str1[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN1 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass1 = new char[N1 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N1; i++)
		{
			pass1[i] = str1[rand() % strN1]; //вставл€ем случайный символ
		}
		pass1[N1] = 0; //записываем в конец строки признак конца строки

		int N2 = 3 + rand() % 3;
		char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN2 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки


		int N3 = 3 + rand() % 3;
		char str3[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN3 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N3; i++)
		{
			pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
		}
		pass3[N3] = 0; //записываем в конец строки признак конца строки

		int N4 = 3 + rand() % 3;
		char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN4 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N4; i++)
		{
			pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
		}
		pass4[N4] = 0; //записываем в конец строки признак конца строки


		int N5 = 3 + rand() % 3;
		char str5[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN5 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass5 = new char[N5 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N5; i++)
		{
			pass5[i] = str5[rand() % strN5]; //вставл€ем случайный символ
		}
		pass5[N5] = 0; //записываем в конец строки признак конца строки

		int N6 = 3 + rand() % 3;
		char str6[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN6 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass6 = new char[N6 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N6; i++)
		{
			pass6[i] = str6[rand() % strN6]; //вставл€ем случайный символ
		}
		pass6[N6] = 0; //записываем в конец строки признак конца строки
		int N7 = 3 + rand() % 3;
		char str7[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN7 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass7 = new char[N7 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N7; i++)
		{
			pass7[i] = str7[rand() % strN7]; //вставл€ем случайный символ
		}
		pass7[N7] = 0; //записываем в конец строки признак конца строки

		int N8 = 3 + rand() % 3;
		char str8[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN8 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass8 = new char[N8 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N8; i++)
		{
			pass8[i] = str8[rand() % strN8]; //вставл€ем случайный символ
		}
		pass8[N8] = 0; //записываем в конец строки признак конца строки

		int N9 = 3 + rand() % 3;
		char str9[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN9 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass9 = new char[N9 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N9; i++)
		{
			pass9[i] = str9[rand() % strN9]; //вставл€ем случайный символ
		}
		pass9[N9] = 0; //записываем в конец строки признак конца строки

		int N10 = 3 + rand() % 3;
		char str10[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN10 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass10 = new char[N10 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N10; i++)
		{
			pass10[i] = str10[rand() % strN10]; //вставл€ем случайный символ
		}
		pass10[N10] = 0; //записываем в конец строки признак конца строки

		int N11 = 3 + rand() % 3;
		char str11[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN11 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass11 = new char[N11 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N11; i++)
		{
			pass11[i] = str11[rand() % strN11]; //вставл€ем случайный символ
		}
		pass11[N11] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << pass << " " << pass1 << " " << pass2 << " " << pass3 << " " << pass4 << " " << pass5 << " " << pass6 << " " << pass7 << " " << pass8 << " " << pass9 << " " << pass10 << " " << pass11;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}

	if (rekey == 49) {
		int N = 3 + rand() % 5;
		char str[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		int N1 = 3 + rand() % 5;
		char str1[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN1 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass1 = new char[N1 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N1; i++)
		{
			pass1[i] = str1[rand() % strN1]; //вставл€ем случайный символ
		}
		pass1[N1] = 0; //записываем в конец строки признак конца строки

		int N2 = 3 + rand() % 5;
		char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN2 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки


		int N3 = 3 + rand() % 5;
		char str3[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN3 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N3; i++)
		{
			pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
		}
		pass3[N3] = 0; //записываем в конец строки признак конца строки

		int N4 = 3 + rand() % 5;
		char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN4 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N4; i++)
		{
			pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
		}
		pass4[N4] = 0; //записываем в конец строки признак конца строки


		int N5 = 3 + rand() % 5;
		char str5[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN5 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass5 = new char[N5 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N5; i++)
		{
			pass5[i] = str5[rand() % strN5]; //вставл€ем случайный символ
		}
		pass5[N5] = 0; //записываем в конец строки признак конца строки

		int N6 = 3 + rand() % 5;
		char str6[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN6 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass6 = new char[N6 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N6; i++)
		{
			pass6[i] = str6[rand() % strN6]; //вставл€ем случайный символ
		}
		pass6[N6] = 0; //записываем в конец строки признак конца строки


		int N7 = 3 + rand() % 5;
		char str7[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN7 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass7 = new char[N7 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N7; i++)
		{
			pass7[i] = str7[rand() % strN7]; //вставл€ем случайный символ
		}
		pass7[N7] = 0; //записываем в конец строки признак конца строки

		int N8 = 3 + rand() % 5;
		char str8[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN8 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass8 = new char[N8 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N8; i++)
		{
			pass8[i] = str8[rand() % strN8]; //вставл€ем случайный символ
		}
		pass8[N8] = 0; //записываем в конец строки признак конца строки

		int N9 = 3 + rand() % 5;
		char str9[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN9 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass9 = new char[N9 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N9; i++)
		{
			pass9[i] = str9[rand() % strN9]; //вставл€ем случайный символ
		}
		pass9[N9] = 0; //записываем в конец строки признак конца строки

		int N10 = 3 + rand() % 5;
		char str10[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN10 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass10 = new char[N10 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N10; i++)
		{
			pass10[i] = str10[rand() % strN10]; //вставл€ем случайный символ
		}
		pass10[N10] = 0; //записываем в конец строки признак конца строки

		int N11 = 3 + rand() % 5;
		char str11[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN11 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass11 = new char[N11 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N11; i++)
		{
			pass11[i] = str11[rand() % strN11]; //вставл€ем случайный символ
		}
		pass11[N11] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << pass << " " << pass1 << " " << pass2 << " " << pass3 << " " << pass4 << " " << pass5 << " " << pass6 << " " << pass7 << " " << pass8 << " " << pass9 << " " << pass10 << " " << pass11;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 50) {
		int N = 3 + rand() % 8;
		char str[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		int N1 = 3 + rand() % 8;
		char str1[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN1 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass1 = new char[N1 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N1; i++)
		{
			pass1[i] = str1[rand() % strN1]; //вставл€ем случайный символ
		}
		pass1[N1] = 0; //записываем в конец строки признак конца строки

		int N2 = 3 + rand() % 8;
		char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN2 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки

		int N3 = 3 + rand() % 8;
		char str3[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN3 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N3; i++)
		{
			pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
		}
		pass3[N3] = 0; //записываем в конец строки признак конца строки

		int N4 = 3 + rand() % 8;
		char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN4 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N4; i++)
		{
			pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
		}
		pass4[N4] = 0; //записываем в конец строки признак конца строки


		int N5 = 3 + rand() % 8;
		char str5[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN5 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass5 = new char[N5 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N5; i++)
		{
			pass5[i] = str5[rand() % strN5]; //вставл€ем случайный символ
		}
		pass5[N5] = 0; //записываем в конец строки признак конца строки

		int N6 = 3 + rand() % 8;
		char str6[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN6 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass6 = new char[N6 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N6; i++)
		{
			pass6[i] = str6[rand() % strN6]; //вставл€ем случайный символ
		}
		pass6[N6] = 0; //записываем в конец строки признак конца строки


		int N7 = 3 + rand() % 8;
		char str7[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN7 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass7 = new char[N7 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N7; i++)
		{
			pass7[i] = str7[rand() % strN7]; //вставл€ем случайный символ
		}
		pass7[N7] = 0; //записываем в конец строки признак конца строки

		int N8 = 3 + rand() % 8;
		char str8[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN8 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass8 = new char[N8 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N8; i++)
		{
			pass8[i] = str8[rand() % strN8]; //вставл€ем случайный символ
		}
		pass8[N8] = 0; //записываем в конец строки признак конца строки

		int N9 = 3 + rand() % 8;
		char str9[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN9 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass9 = new char[N9 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N9; i++)
		{
			pass9[i] = str9[rand() % strN9]; //вставл€ем случайный символ
		}
		pass9[N9] = 0; //записываем в конец строки признак конца строки

		int N10 = 3 + rand() % 8;
		char str10[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN10 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass10 = new char[N10 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N10; i++)
		{
			pass10[i] = str10[rand() % strN10]; //вставл€ем случайный символ
		}
		pass10[N10] = 0; //записываем в конец строки признак конца строки

		int N11 = 3 + rand() % 8;
		char str11[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN11 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass11 = new char[N11 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N11; i++)
		{
			pass11[i] = str11[rand() % strN11]; //вставл€ем случайный символ
		}
		pass11[N11] = 0; //записываем в конец строки признак конца строки

		std::stringstream ss;
		ss << pass << " " << pass1 << " " << pass2 << " " << pass3 << " " << pass4 << " " << pass5 << " " << pass6 << " " << pass7 << " " << pass8 << " " << pass9 << " " << pass10 << " " << pass11;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}

	if (rekey == 51) {
		int N = 3 + rand() % 10;
		char str[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки

		int N1 = 3 + rand() % 10;
		char str1[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN1 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass1 = new char[N1 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N1; i++)
		{
			pass1[i] = str1[rand() % strN1]; //вставл€ем случайный символ
		}
		pass1[N1] = 0; //записываем в конец строки признак конца строки

		int N2 = 3 + rand() % 10;
		char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN2 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N2; i++)
		{
			pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
		}
		pass2[N2] = 0; //записываем в конец строки признак конца строки


		int N3 = 3 + rand() % 10;
		char str3[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN3 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N3; i++)
		{
			pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
		}
		pass3[N3] = 0; //записываем в конец строки признак конца строки

		int N4 = 3 + rand() % 10;
		char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN4 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N4; i++)
		{
			pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
		}
		pass4[N4] = 0; //записываем в конец строки признак конца строки


		int N5 = 3 + rand() % 10;
		char str5[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN5 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass5 = new char[N5 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N5; i++)
		{
			pass5[i] = str5[rand() % strN5]; //вставл€ем случайный символ
		}
		pass5[N5] = 0; //записываем в конец строки признак конца строки

		int N6 = 3 + rand() % 10;
		char str6[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN6 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass6 = new char[N6 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N6; i++)
		{
			pass6[i] = str6[rand() % strN6]; //вставл€ем случайный символ
		}
		pass6[N6] = 0; //записываем в конец строки признак конца строки


		int N7 = 3 + rand() % 10;
		char str7[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN7 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass7 = new char[N7 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N7; i++)
		{
			pass7[i] = str7[rand() % strN7]; //вставл€ем случайный символ
		}
		pass7[N7] = 0; //записываем в конец строки признак конца строки

		int N8 = 3 + rand() % 10;
		char str8[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN8 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass8 = new char[N8 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N8; i++)
		{
			pass8[i] = str8[rand() % strN8]; //вставл€ем случайный символ
		}
		pass8[N8] = 0; //записываем в конец строки признак конца строки

		int N9 = 3 + rand() % 10;
		char str9[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN9 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass9 = new char[N9 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N9; i++)
		{
			pass9[i] = str9[rand() % strN9]; //вставл€ем случайный символ
		}
		pass9[N9] = 0; //записываем в конец строки признак конца строки

		int N10 = 3 + rand() % 10;
		char str10[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN10 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass10 = new char[N10 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N10; i++)
		{
			pass10[i] = str10[rand() % strN10]; //вставл€ем случайный символ
		}
		pass10[N10] = 0; //записываем в конец строки признак конца строки

		int N11 = 3 + rand() % 10;
		char str11[]{ "abcdefghijklmnopqrstuvwxyz" };
		int strN11 = 26; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass11 = new char[N11 + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N11; i++)
		{
			pass11[i] = str11[rand() % strN11]; //вставл€ем случайный символ
		}
		pass11[N11] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << pass << " " << pass1 << " " << pass2 << " " << pass3 << " " << pass4 << " " << pass5 << " " << pass6 << " " << pass7 << " " << pass8 << " " << pass9 << " " << pass10 << " " << pass11;
		std::string input = ss.str();
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", input.c_str());
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", input.c_str(), key.GetBase16().c_str());
		}

	}
	if (rekey == 52) {
		int N = nbit;
		char str[]{ "0123456789abcdef" };
		int strN = 16; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		std::stringstream ss;
		ss << seed << pass;
		std::string input = ss.str();
		char* cstr = &input[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", key.GetBase16().c_str());
		}
		if (diz == 1) {
			printf("\r [%s] ", key.GetBase16().c_str());
		}
	}

	if (rekey == 53) {
		
		if (nbit == 0) {
			int N = 1 + rand() % 65;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s]  ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		
		if (nbit == 1) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;
			std::stringstream ss;
			ss << pass2;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 2) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;
			std::stringstream ss;
			ss << pass2;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 3) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;
			std::stringstream ss;
			ss << pass2;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 4) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			std::stringstream ss;
			ss << pass2;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 5) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 6) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 7) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 8) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 9) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 10) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 11) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 12) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 13) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 14) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 15) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 16) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 17) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 18) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 19) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 20) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 21) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 22) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 23) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 24) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 25) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 26) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 27) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 28) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 29) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 30) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 31) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 32) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 33) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 34) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 35) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 36) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 37) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 38) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 39) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 40) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 41) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 42) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 43) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 44) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 45) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 46) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 47) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 48) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 49) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 50) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 51) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 52) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 53) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 54) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 55) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 56) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 57) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 58) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 59) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 60) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 61) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 62) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 63) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 64) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 65) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 66) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 67) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 68) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 69) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 70) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 71) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 72) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 73) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 74) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 75) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 76) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 77) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 78) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 79) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 80) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 81) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 82) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 83) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 84) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 85) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 86) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 87) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 88) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 89) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 90) {
			int N2 = 4;
			char str2[]{ "4567" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 91) {
			int N2 = 4;
			char str2[]{ "89ab" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 92) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 93) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 94) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 95) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 96) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 97) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 98) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 99) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 100) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 101) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 102) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 103) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 104) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 105) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 106) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 107) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 108) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 109) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 110) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 111) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 112) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 113) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 114) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 115) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 116) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 117) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 118) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 119) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 120) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 121) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 122) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 123) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 124) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 125) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 126) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 127) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 128) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 129) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 130) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 131) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 132) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 133) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 134) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 135) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 136) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 137) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 138) {
			int N2 = 4;
			char str2[]{ "4567" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 139) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 140) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 141) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 142) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 143) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 144) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 145) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 146) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 147) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 148) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 149) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 150) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 151) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 152) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 153) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 154) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 155) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 156) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 157) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 158) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 159) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 160) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 161) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 162) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 163) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 164) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 165) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 166) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 167) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 168) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 169) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 170) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 171) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 172) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 173) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 174) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 175) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 176) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 177) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 178) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 179) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 180) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 181) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 182) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 183) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 184) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 185) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 186) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 187) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 188) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 189) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 190) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 191) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 192) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 193) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 194) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 195) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 196) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 197) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 198) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 199) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 200) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 201) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 202) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 203) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 204) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}



		if (nbit == 205) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 206) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 207) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 208) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 209) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 210) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 211) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 212) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 213) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 214) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 215) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 216) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}



		if (nbit == 217) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 218) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 219) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 220) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}



		if (nbit == 221) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 222) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 223) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 224) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


		if (nbit == 225) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 226) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 227) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 228) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 229) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 230) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 231) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 232) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 233) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 234) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 235) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 236) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}

		if (nbit == 237) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 238) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 239) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 240) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}

		if (nbit == 241) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 242) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 243) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 244) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}

		if (nbit == 245) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 246) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 247) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 248) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 249) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 250) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 251) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 252) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}
		}
		if (nbit == 253) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 254) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 255) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (nbit == 256) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}


	}

	if (rekey == 54) {
		string initial = seed;
		string str = initial;
		string last;
		do {
			last = str;
			str = increment(last);
			string input = str;
			string nos = sha256(input);
			char* cstr = &nos[0];
			key.SetBase16(cstr);

			if (diz == 0) {
				printf("\r [%s] ", str.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s]", str.c_str(), key.GetBase16().c_str());
			}
		} while (compare(last, str));
	}
	if (rekey == 55) {
		int N = nbit;
		char str[]{ "!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
		int strN = 31; // индекс последнего элемента в массиве
		//srand(time(NULL)); //инициализируем генератор случайных чисел
		char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
		for (int i = 0; i < N; i++)
		{
			pass[i] = str[rand() % strN]; //вставл€ем случайный символ
		}
		pass[N] = 0; //записываем в конец строки признак конца строки
		string input = pass;
		string nos = sha256(input);
		char* cstr = &nos[0];
		key.SetBase16(cstr);
		if (diz == 0) {
			printf("\r [%s] ", pass);
		}
		if (diz == 1) {
			printf("\r [%s] [%s] ", pass, key.GetBase16().c_str());
		}

	}


	if (rekey == 56) {

		char* gyg = &seed[0];

		char* fun = &zez[0];
		this->rangeStart1.SetBase16(gyg);
		this->rangeEnd1.SetBase16(fun);
		


		this->rangeDiff2.Set(&this->rangeEnd1);
		this->rangeDiff2.Sub(&this->rangeStart1);
		
		this->rangeDiff3.Set(&this->rangeStart1);
		
		int tuk = rangeDiff2.GetBitLength();
		
		int br = rand() % tuk;
			

		if (br == 1) {
			int N = 1;

			char str[]{ "0123" };
			int strN = 4;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 2) {
			int N = 1;
			char str[]{ "4567" };
			int strN = 4;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;

			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 3) {
			int N = 1;

			char str[]{ "89ab" };
			int strN = 4;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 4) {
			int N = 1;
			char str[]{ "cdef" };
			int strN = 4;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;

			std::stringstream ss;
			ss << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 5) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 6) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 7) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;
			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 8) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 1;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 9) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 10) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 11) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 12) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 2;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 13) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 14) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 15) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 16) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 3;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 17) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 18) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 19) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 20) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 4;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 21) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 22) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 23) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 24) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 5;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 25) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 26) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 27) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 28) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 6;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 29) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 30) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 31) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 32) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 7;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 33) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 34) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 35) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 36) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 8;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 37) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 38) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 39) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 40) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 9;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 41) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 42) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 43) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 44) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 10;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 45) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 46) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 47) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 48) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 11;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}

		if (br == 49) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 50) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 51) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 52) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 12;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 53) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 54) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 55) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 56) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 13;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 57) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 58) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 59) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 60) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 14;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 61) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 62) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 63) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 64) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 15;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 65) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 66) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 67) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 68) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 16;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 69) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 70) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 71) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 72) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 17;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 73) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 74) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 75) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 76) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 18;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}

		if (br == 77) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 78) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 79) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 80) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 19;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 81) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 82) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 83) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 84) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 20;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 85) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 86) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 87) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 88) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 21;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 89) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 90) {
			int N2 = 4;
			char str2[]{ "4567" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 91) {
			int N2 = 4;
			char str2[]{ "89ab" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 92) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 22;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 93) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 94) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 95) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 96) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 23;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}

		if (br == 97) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 98) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 99) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 100) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 24;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 101) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 102) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 103) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 104) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 25;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 105) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 106) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 107) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 108) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 26;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 109) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 110) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 111) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 112) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 27;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 113) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 114) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 115) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 116) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 28;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 117) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 118) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 119) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 120) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 29;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}

		if (br == 121) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 122) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 123) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 124) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 30;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 125) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 126) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 127) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 128) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 31;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 129) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 130) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 131) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 132) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 32;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 133) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 134) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 135) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 136) {
			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 33;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 137) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 138) {
			int N2 = 4;
			char str2[]{ "4567" };
			int strN2 = 1;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 139) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 140) {
			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 34;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 141) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.SetBase16(cstr);
			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r [%s] (%d bit) ", key.GetBase16().c_str(), key.GetBitLength());
			}

		}
		if (br == 142) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 143) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 144) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 35;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 145) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 146) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 147) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 148) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 36;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 149) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 150) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 151) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 152) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 37;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 153) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 154) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 155) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 156) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 38;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 157) {
			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 158) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 159) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 160) {
			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 39;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 161) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 162) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 163) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 164) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 40;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 165) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 166) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 167) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 168) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 41;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 169) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 170) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 171) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 172) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 42;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 173) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 174) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 175) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 176) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 43;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 177) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 178) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 179) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 180) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 44;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 181) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 182) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 183) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 184) {
			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 45;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 185) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 186) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 187) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 188) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 46;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 189) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 190) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 191) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 192) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 47;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 193) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 194) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 195) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 196) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 48;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 197) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 198) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 199) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 200) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 49;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 201) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 202) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 203) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 204) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 50;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 205) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 206) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 207) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 208) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 51;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 209) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 210) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 211) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 212) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 52;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 213) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 214) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 215) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 216) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 53;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 217) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 218) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 219) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 220) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 54;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 221) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 222) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 223) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 224) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 55;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 225) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 226) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 227) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 228) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 56;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 229) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 230) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 231) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 232) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 57;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 233) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 234) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 235) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 236) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 58;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 237) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 238) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 239) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 240) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 59;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}

		if (br == 241) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 242) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 243) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}
		if (br == 244) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 60;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 245) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 246) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 247) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 248) {

			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 61;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 249) {

			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;

			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 250) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 251) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Set(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 252) {
			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 62;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 253) {
			int N2 = 1;
			char str2[]{ "0123" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 254) {
			int N2 = 1;
			char str2[]{ "4567" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 255) {
			int N2 = 1;
			char str2[]{ "89ab" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}
		}
		if (br == 256) {
			int N2 = 1;
			char str2[]{ "cdef" };
			int strN2 = 4;
			char* pass2 = new char[N2 + 1];
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2];
			}
			pass2[N2] = 0;

			int N = 63;
			char str[]{ "0123456789abcdef" };
			int strN = 16;
			char* pass = new char[N + 1];
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN];
			}
			pass[N] = 0;
			std::stringstream ss;
			ss << pass2 << pass;
			std::string input = ss.str();
			char* cstr = &input[0];
			key22.SetBase16(cstr);
			this->rangeDiff3.Add(&key22);
			key.Set(&rangeDiff3);

			if (diz == 0) {
				printf("\r (%d bit) ", key.GetBitLength());
			}
			if (diz == 1) {
				printf("\r (%d bit) [%s] ", key.GetBitLength(), key.GetBase16().c_str());
			}

		}


	}
	
	
	
	
	Int km(&key);
	km.Add((uint64_t)CPU_GRP_SIZE / 2);
	startP = secp->ComputePublicKey(&km);

}

void LostCoins::FindKeyCPU(TH_PARAM *ph)
{

	// Global init
	int thId = ph->threadId;
	counters[thId] = 0;

	// CPU Thread
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);

	// Group Init
	Int  key;
	Point startP;
	getCPUStartingKey(thId, key, startP);

	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];

	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	grp->Set(dx);

	ph->hasStarted = true;
	ph->rekeyRequest = false;

	while (!endOfSearch) {

		if (ph->rekeyRequest) {
			getCPUStartingKey(thId, key, startP);
			ph->rekeyRequest = false;
		}

		// Fill group
		int i;
		int hLength = (CPU_GRP_SIZE / 2 - 1);

		for (i = 0; i < hLength; i++) {
			dx[i].ModSub(&Gn[i].x, &startP.x);
		}
		dx[i].ModSub(&Gn[i].x, &startP.x);  // For the first point
		dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point

		// Grouped ModInv
		grp->ModInv();

		// We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
		// We compute key in the positive and negative way from the center of the group

		// center point
		pts[CPU_GRP_SIZE / 2] = startP;

		for (i = 0; i < hLength && !endOfSearch; i++) {

			pp = startP;
			pn = startP;

			// P = startP + i*G
			dy.ModSub(&Gn[i].y, &pp.y);

			_s.ModMulK1(&dy, &dx[i]);       // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
			_p.ModSquareK1(&_s);            // _p = pow2(s)

			pp.x.ModNeg();
			pp.x.ModAdd(&_p);
			pp.x.ModSub(&Gn[i].x);           // rx = pow2(s) - p1.x - p2.x;

			pp.y.ModSub(&Gn[i].x, &pp.x);
			pp.y.ModMulK1(&_s);
			pp.y.ModSub(&Gn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);

			// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
			dyn.Set(&Gn[i].y);
			dyn.ModNeg();
			dyn.ModSub(&pn.y);

			_s.ModMulK1(&dyn, &dx[i]);      // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
			_p.ModSquareK1(&_s);            // _p = pow2(s)

			pn.x.ModNeg();
			pn.x.ModAdd(&_p);
			pn.x.ModSub(&Gn[i].x);          // rx = pow2(s) - p1.x - p2.x;

			pn.y.ModSub(&Gn[i].x, &pn.x);
			pn.y.ModMulK1(&_s);
			pn.y.ModAdd(&Gn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);

			pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
			pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;

		}

		// First point (startP - (GRP_SZIE/2)*G)
		pn = startP;
		dyn.Set(&Gn[i].y);
		dyn.ModNeg();
		dyn.ModSub(&pn.y);

		_s.ModMulK1(&dyn, &dx[i]);
		_p.ModSquareK1(&_s);

		pn.x.ModNeg();
		pn.x.ModAdd(&_p);
		pn.x.ModSub(&Gn[i].x);

		pn.y.ModSub(&Gn[i].x, &pn.x);
		pn.y.ModMulK1(&_s);
		pn.y.ModAdd(&Gn[i].y);

		pts[0] = pn;

		// Next start point (startP + GRP_SIZE*G)
		pp = startP;
		dy.ModSub(&_2Gn.y, &pp.y);

		_s.ModMulK1(&dy, &dx[i + 1]);
		_p.ModSquareK1(&_s);

		pp.x.ModNeg();
		pp.x.ModAdd(&_p);
		pp.x.ModSub(&_2Gn.x);

		pp.y.ModSub(&_2Gn.x, &pp.x);
		pp.y.ModMulK1(&_s);
		pp.y.ModSub(&_2Gn.y);
		startP = pp;

		// Check addresses
		if (useSSE) {

			for (int i = 0; i < CPU_GRP_SIZE && !endOfSearch; i += 4) {

				switch (searchMode) {
				case SEARCH_COMPRESSED:
					checkAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					break;
				case SEARCH_UNCOMPRESSED:
					checkAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					break;
				case SEARCH_BOTH:
					checkAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					checkAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					break;
				}
			}
		}
		else {

			for (int i = 0; i < CPU_GRP_SIZE && !endOfSearch; i++) {

				switch (searchMode) {
				case SEARCH_COMPRESSED:
					checkAddresses(true, key, i, pts[i]);
					break;
				case SEARCH_UNCOMPRESSED:
					checkAddresses(false, key, i, pts[i]);
					break;
				case SEARCH_BOTH:
					checkAddresses(true, key, i, pts[i]);
					checkAddresses(false, key, i, pts[i]);
					break;
				}
			}
		}

		key.Add((uint64_t)CPU_GRP_SIZE);
		counters[thId] += 6 * CPU_GRP_SIZE; // Point + endo #1 + endo #2 + Symetric point + endo #1 + endo #2
	}
	ph->isRunning = false;
}

// ----------------------------------------------------------------------------

void LostCoins::getGPUStartingKeys(int thId, int groupSize, int nbThread, Int *keys, Point *p)
{
	
	for (int i = 0; i < nbThread; i++) {
		
		if (rekey == 0) {

			int N = 3 + rand() % 7;
			char str[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}
		}
		if (rekey == 1) {
			keys[i].Rand(nbit);
			if (diz == 1) {
				printf("\r [%s] ", keys[i].GetBase16().c_str());
			}
		}
		if (rekey == 2) {
			keys[i].Rand(nbit);
			if (diz == 1) {
				printf("\r [%s] ", keys[i].GetBase16().c_str());
			}
		}
		if (rekey == 3) {
			keys[i].Rand(nbit);
			if (diz == 1) {
				printf("\r [%s] ", keys[i].GetBase16().c_str());
			}
		}

		if (rekey == 4) {
			int N = nbit;
			char str[]{ "0123456789" };
			int strN = 10; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 5) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 6) {
			int N = nbit;
			char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 7) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyz0123456789" };
			int strN = 36; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 8) {
			int N = nbit;
			char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
			int strN = 36; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 9) {
			int N = nbit;
			char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };
			int strN = 52; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 10) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
			int strN = 62; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 11) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
			int strN = 93; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 12) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "абвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
			int strN = 33; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 13) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя" };
			int strN = 33; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 14) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
			int strN = 66; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 15) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789" };
			int strN = 76; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 16) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
			int strN = 107; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 17) {
			int N = nbit;
			char str[]{ "0123456789" };
			int strN = 10; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}
		}
		if (rekey == 18) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 19) {
			int N = nbit;
			char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 20) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyz0123456789" };
			int strN = 36; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 21) {
			int N = nbit;
			char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
			int strN = 36; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 22) {
			int N = nbit;
			char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };
			int strN = 52; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 23) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
			int strN = 62; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 24) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
			int strN = 92; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 25) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "абвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
			int strN = 33; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 26) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя" };
			int strN = 33; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 27) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
			int strN = 66; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 28) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789" };
			int strN = 76; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 29) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
			int strN = 106; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 30) {
			int N = nbit;
			char str[]{ "0123456789" };
			int strN = 10; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 31) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 32) {
			int N = nbit;
			char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 33) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyz0123456789" };
			int strN = 36; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 34) {
			int N = nbit;
			char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
			int strN = 36; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 35) {
			int N = nbit;
			char str[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };
			int strN = 52; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 36) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };
			int strN = 62; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 37) {
			int N = nbit;
			char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
			int strN = 93; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 38) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "абвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
			int strN = 33; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 39) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя" };
			int strN = 33; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 40) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€" };
			int strN = 66; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 41) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789" };
			int strN = 76; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 42) {
			setlocale(LC_ALL, "Russian");
			int N = nbit;
			char str[]{ "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№ЁёяабвгдеЄжзийклмнопрстуфхцчшщъыьэю€0123456789!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
			int strN = 107; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			std::stringstream ss;
			ss << seed << " " << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}
		}

		if (rekey == 43) {
			int N = 2;
			char str[]{ "0123456789" };
			int strN = 10; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			int N2 = nbit;
			char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN2 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки

			int N3 = 1;
			char str3[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
			int strN3 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N3; i++)
			{
				pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
			}
			pass3[N3] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << pass3 << pass2 << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 44) {
			int N = 4;
			char str[]{ "0123456789" };
			int strN = 10; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			int N2 = nbit;
			char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN2 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки

			int N3 = 1;
			char str3[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
			int strN3 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N3; i++)
			{
				pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
			}
			pass3[N3] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << pass3 << pass2 << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 45) {
			int N = 6;
			char str[]{ "0123456789" };
			int strN = 10; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			int N2 = nbit;
			char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN2 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки

			int N3 = 1;
			char str3[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
			int strN3 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N3; i++)
			{
				pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
			}
			pass3[N3] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << pass3 << pass2 << pass;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}

		if (rekey == 46) {
			int N2 = 3 + rand() % 7;
			char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN2 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки

			int N4 = 3 + rand() % 7;
			char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN4 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N4; i++)
			{
				pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
			}
			pass4[N4] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << pass2 << " " << pass4;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 47) {
			int N2 = 3 + rand() % 7;
			char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN2 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки
			int N4 = 3 + rand() % 7;
			char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN4 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N4; i++)
			{
				pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
			}
			pass4[N4] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << seed << " " << pass2 << " " << pass4;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}
		}
		if (rekey == 48) {
			int N = 3 + rand() % 3;
			char str[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			int N1 = 3 + rand() % 3;
			char str1[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN1 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass1 = new char[N1 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N1; i++)
			{
				pass1[i] = str1[rand() % strN1]; //вставл€ем случайный символ
			}
			pass1[N1] = 0; //записываем в конец строки признак конца строки

			int N2 = 3 + rand() % 3;
			char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN2 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки


			int N3 = 3 + rand() % 3;
			char str3[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN3 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N3; i++)
			{
				pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
			}
			pass3[N3] = 0; //записываем в конец строки признак конца строки

			int N4 = 3 + rand() % 3;
			char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN4 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N4; i++)
			{
				pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
			}
			pass4[N4] = 0; //записываем в конец строки признак конца строки


			int N5 = 3 + rand() % 3;
			char str5[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN5 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass5 = new char[N5 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N5; i++)
			{
				pass5[i] = str5[rand() % strN5]; //вставл€ем случайный символ
			}
			pass5[N5] = 0; //записываем в конец строки признак конца строки

			int N6 = 3 + rand() % 3;
			char str6[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN6 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass6 = new char[N6 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N6; i++)
			{
				pass6[i] = str6[rand() % strN6]; //вставл€ем случайный символ
			}
			pass6[N6] = 0; //записываем в конец строки признак конца строки
			int N7 = 3 + rand() % 3;
			char str7[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN7 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass7 = new char[N7 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N7; i++)
			{
				pass7[i] = str7[rand() % strN7]; //вставл€ем случайный символ
			}
			pass7[N7] = 0; //записываем в конец строки признак конца строки

			int N8 = 3 + rand() % 3;
			char str8[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN8 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass8 = new char[N8 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N8; i++)
			{
				pass8[i] = str8[rand() % strN8]; //вставл€ем случайный символ
			}
			pass8[N8] = 0; //записываем в конец строки признак конца строки

			int N9 = 3 + rand() % 3;
			char str9[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN9 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass9 = new char[N9 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N9; i++)
			{
				pass9[i] = str9[rand() % strN9]; //вставл€ем случайный символ
			}
			pass9[N9] = 0; //записываем в конец строки признак конца строки

			int N10 = 3 + rand() % 3;
			char str10[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN10 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass10 = new char[N10 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N10; i++)
			{
				pass10[i] = str10[rand() % strN10]; //вставл€ем случайный символ
			}
			pass10[N10] = 0; //записываем в конец строки признак конца строки

			int N11 = 3 + rand() % 3;
			char str11[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN11 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass11 = new char[N11 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N11; i++)
			{
				pass11[i] = str11[rand() % strN11]; //вставл€ем случайный символ
			}
			pass11[N11] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << pass << " " << pass1 << " " << pass2 << " " << pass3 << " " << pass4 << " " << pass5 << " " << pass6 << " " << pass7 << " " << pass8 << " " << pass9 << " " << pass10 << " " << pass11;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}

		if (rekey == 49) {
			int N = 3 + rand() % 5;
			char str[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			int N1 = 3 + rand() % 5;
			char str1[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN1 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass1 = new char[N1 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N1; i++)
			{
				pass1[i] = str1[rand() % strN1]; //вставл€ем случайный символ
			}
			pass1[N1] = 0; //записываем в конец строки признак конца строки

			int N2 = 3 + rand() % 5;
			char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN2 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки


			int N3 = 3 + rand() % 5;
			char str3[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN3 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N3; i++)
			{
				pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
			}
			pass3[N3] = 0; //записываем в конец строки признак конца строки

			int N4 = 3 + rand() % 5;
			char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN4 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N4; i++)
			{
				pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
			}
			pass4[N4] = 0; //записываем в конец строки признак конца строки


			int N5 = 3 + rand() % 5;
			char str5[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN5 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass5 = new char[N5 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N5; i++)
			{
				pass5[i] = str5[rand() % strN5]; //вставл€ем случайный символ
			}
			pass5[N5] = 0; //записываем в конец строки признак конца строки

			int N6 = 3 + rand() % 5;
			char str6[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN6 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass6 = new char[N6 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N6; i++)
			{
				pass6[i] = str6[rand() % strN6]; //вставл€ем случайный символ
			}
			pass6[N6] = 0; //записываем в конец строки признак конца строки


			int N7 = 3 + rand() % 5;
			char str7[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN7 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass7 = new char[N7 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N7; i++)
			{
				pass7[i] = str7[rand() % strN7]; //вставл€ем случайный символ
			}
			pass7[N7] = 0; //записываем в конец строки признак конца строки

			int N8 = 3 + rand() % 5;
			char str8[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN8 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass8 = new char[N8 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N8; i++)
			{
				pass8[i] = str8[rand() % strN8]; //вставл€ем случайный символ
			}
			pass8[N8] = 0; //записываем в конец строки признак конца строки

			int N9 = 3 + rand() % 5;
			char str9[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN9 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass9 = new char[N9 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N9; i++)
			{
				pass9[i] = str9[rand() % strN9]; //вставл€ем случайный символ
			}
			pass9[N9] = 0; //записываем в конец строки признак конца строки

			int N10 = 3 + rand() % 5;
			char str10[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN10 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass10 = new char[N10 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N10; i++)
			{
				pass10[i] = str10[rand() % strN10]; //вставл€ем случайный символ
			}
			pass10[N10] = 0; //записываем в конец строки признак конца строки

			int N11 = 3 + rand() % 5;
			char str11[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN11 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass11 = new char[N11 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N11; i++)
			{
				pass11[i] = str11[rand() % strN11]; //вставл€ем случайный символ
			}
			pass11[N11] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << pass << " " << pass1 << " " << pass2 << " " << pass3 << " " << pass4 << " " << pass5 << " " << pass6 << " " << pass7 << " " << pass8 << " " << pass9 << " " << pass10 << " " << pass11;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 50) {
			int N = 3 + rand() % 8;
			char str[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			int N1 = 3 + rand() % 8;
			char str1[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN1 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass1 = new char[N1 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N1; i++)
			{
				pass1[i] = str1[rand() % strN1]; //вставл€ем случайный символ
			}
			pass1[N1] = 0; //записываем в конец строки признак конца строки

			int N2 = 3 + rand() % 8;
			char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN2 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки

			int N3 = 3 + rand() % 8;
			char str3[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN3 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N3; i++)
			{
				pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
			}
			pass3[N3] = 0; //записываем в конец строки признак конца строки

			int N4 = 3 + rand() % 8;
			char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN4 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N4; i++)
			{
				pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
			}
			pass4[N4] = 0; //записываем в конец строки признак конца строки


			int N5 = 3 + rand() % 8;
			char str5[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN5 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass5 = new char[N5 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N5; i++)
			{
				pass5[i] = str5[rand() % strN5]; //вставл€ем случайный символ
			}
			pass5[N5] = 0; //записываем в конец строки признак конца строки

			int N6 = 3 + rand() % 8;
			char str6[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN6 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass6 = new char[N6 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N6; i++)
			{
				pass6[i] = str6[rand() % strN6]; //вставл€ем случайный символ
			}
			pass6[N6] = 0; //записываем в конец строки признак конца строки


			int N7 = 3 + rand() % 8;
			char str7[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN7 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass7 = new char[N7 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N7; i++)
			{
				pass7[i] = str7[rand() % strN7]; //вставл€ем случайный символ
			}
			pass7[N7] = 0; //записываем в конец строки признак конца строки

			int N8 = 3 + rand() % 8;
			char str8[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN8 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass8 = new char[N8 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N8; i++)
			{
				pass8[i] = str8[rand() % strN8]; //вставл€ем случайный символ
			}
			pass8[N8] = 0; //записываем в конец строки признак конца строки

			int N9 = 3 + rand() % 8;
			char str9[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN9 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass9 = new char[N9 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N9; i++)
			{
				pass9[i] = str9[rand() % strN9]; //вставл€ем случайный символ
			}
			pass9[N9] = 0; //записываем в конец строки признак конца строки

			int N10 = 3 + rand() % 8;
			char str10[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN10 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass10 = new char[N10 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N10; i++)
			{
				pass10[i] = str10[rand() % strN10]; //вставл€ем случайный символ
			}
			pass10[N10] = 0; //записываем в конец строки признак конца строки

			int N11 = 3 + rand() % 8;
			char str11[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN11 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass11 = new char[N11 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N11; i++)
			{
				pass11[i] = str11[rand() % strN11]; //вставл€ем случайный символ
			}
			pass11[N11] = 0; //записываем в конец строки признак конца строки

			std::stringstream ss;
			ss << pass << " " << pass1 << " " << pass2 << " " << pass3 << " " << pass4 << " " << pass5 << " " << pass6 << " " << pass7 << " " << pass8 << " " << pass9 << " " << pass10 << " " << pass11;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}

		if (rekey == 51) {
			int N = 3 + rand() % 10;
			char str[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки

			int N1 = 3 + rand() % 10;
			char str1[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN1 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass1 = new char[N1 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N1; i++)
			{
				pass1[i] = str1[rand() % strN1]; //вставл€ем случайный символ
			}
			pass1[N1] = 0; //записываем в конец строки признак конца строки

			int N2 = 3 + rand() % 10;
			char str2[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN2 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass2 = new char[N2 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N2; i++)
			{
				pass2[i] = str2[rand() % strN2]; //вставл€ем случайный символ
			}
			pass2[N2] = 0; //записываем в конец строки признак конца строки


			int N3 = 3 + rand() % 10;
			char str3[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN3 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass3 = new char[N3 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N3; i++)
			{
				pass3[i] = str3[rand() % strN3]; //вставл€ем случайный символ
			}
			pass3[N3] = 0; //записываем в конец строки признак конца строки

			int N4 = 3 + rand() % 10;
			char str4[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN4 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass4 = new char[N4 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N4; i++)
			{
				pass4[i] = str4[rand() % strN4]; //вставл€ем случайный символ
			}
			pass4[N4] = 0; //записываем в конец строки признак конца строки


			int N5 = 3 + rand() % 10;
			char str5[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN5 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass5 = new char[N5 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N5; i++)
			{
				pass5[i] = str5[rand() % strN5]; //вставл€ем случайный символ
			}
			pass5[N5] = 0; //записываем в конец строки признак конца строки

			int N6 = 3 + rand() % 10;
			char str6[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN6 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass6 = new char[N6 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N6; i++)
			{
				pass6[i] = str6[rand() % strN6]; //вставл€ем случайный символ
			}
			pass6[N6] = 0; //записываем в конец строки признак конца строки


			int N7 = 3 + rand() % 10;
			char str7[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN7 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass7 = new char[N7 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N7; i++)
			{
				pass7[i] = str7[rand() % strN7]; //вставл€ем случайный символ
			}
			pass7[N7] = 0; //записываем в конец строки признак конца строки

			int N8 = 3 + rand() % 10;
			char str8[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN8 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass8 = new char[N8 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N8; i++)
			{
				pass8[i] = str8[rand() % strN8]; //вставл€ем случайный символ
			}
			pass8[N8] = 0; //записываем в конец строки признак конца строки

			int N9 = 3 + rand() % 10;
			char str9[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN9 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass9 = new char[N9 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N9; i++)
			{
				pass9[i] = str9[rand() % strN9]; //вставл€ем случайный символ
			}
			pass9[N9] = 0; //записываем в конец строки признак конца строки

			int N10 = 3 + rand() % 10;
			char str10[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN10 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass10 = new char[N10 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N10; i++)
			{
				pass10[i] = str10[rand() % strN10]; //вставл€ем случайный символ
			}
			pass10[N10] = 0; //записываем в конец строки признак конца строки

			int N11 = 3 + rand() % 10;
			char str11[]{ "abcdefghijklmnopqrstuvwxyz" };
			int strN11 = 26; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass11 = new char[N11 + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N11; i++)
			{
				pass11[i] = str11[rand() % strN11]; //вставл€ем случайный символ
			}
			pass11[N11] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << pass << " " << pass1 << " " << pass2 << " " << pass3 << " " << pass4 << " " << pass5 << " " << pass6 << " " << pass7 << " " << pass8 << " " << pass9 << " " << pass10 << " " << pass11;
			std::string input = ss.str();
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", input.c_str());
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", input.c_str(), keys[i].GetBase16().c_str());
			}

		}
		if (rekey == 52) {
			int N = nbit;
			char str[]{ "0123456789abcdef" };
			int strN = 16; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			std::stringstream ss;
			ss << seed << pass;
			std::string input = ss.str();
			//string nos = sha256(input);
			char* cstr = &input[0];
			keys[i].SetBase16(cstr);
			if (diz == 1) {
				printf("\r [%s] ", keys[i].GetBase16().c_str());
			}
		}

		if (rekey == 53) {

			if (nbit == 0) {
				int N = 1 + rand() % 65;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit == 1) {

				int N = 30 + rand() % 35;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit == 3) {
				int N = 40 + rand() % 25;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit == 4) {
				int N = 50 + rand() % 15;

				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s]  ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (nbit == 5) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 6) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 7) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 8) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 9) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 10) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 11) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 12) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 13) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 14) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 15) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 16) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 17) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 18) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 19) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 20) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 21) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 22) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 23) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 24) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 25) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 26) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 27) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 28) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 29) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 30) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 31) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 32) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 33) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 34) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 35) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 36) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 37) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 38) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 39) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 40) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 41) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 42) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 43) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 44) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 45) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 46) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 47) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 48) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 49) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 50) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 51) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 52) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 53) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 54) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 55) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 56) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 57) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 58) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 59) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 60) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 61) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 62) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 63) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 64) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 65) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 66) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 67) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 68) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 69) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 70) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 71) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 72) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 73) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 74) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 75) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 76) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 77) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 78) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 79) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 80) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 81) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 82) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 83) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 84) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}

			if (nbit == 85) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 86) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 87) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 88) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 89) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 90) {
				int N2 = 4;
				char str2[]{ "4567" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 91) {
				int N2 = 4;
				char str2[]{ "89ab" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 92) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 93) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 94) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 95) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 96) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 97) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 98) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 99) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 100) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 101) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 102) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 103) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 104) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 105) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 106) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 107) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 108) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 109) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 110) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 111) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 112) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 113) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 114) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 115) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 116) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 117) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 118) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 119) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 120) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 121) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 122) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 123) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 124) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 125) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 126) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 127) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 128) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 129) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 130) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 131) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 132) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 133) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 134) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 135) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 136) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 137) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 138) {
				int N2 = 4;
				char str2[]{ "4567" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 139) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 140) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 141) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 142) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 143) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 144) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 145) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 146) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 147) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 148) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 149) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 150) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 151) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 152) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 153) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 154) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 155) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 156) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 157) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 158) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 159) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 160) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 161) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 162) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 163) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 164) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 165) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 166) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 167) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 168) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 169) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 170) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 171) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 172) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 173) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 174) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 175) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 176) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 177) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 178) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 179) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 180) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 181) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 182) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 183) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 184) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 185) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 186) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 187) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 188) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 189) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 190) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 191) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 192) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 193) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 194) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 195) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 196) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 197) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 198) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 199) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 200) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


			if (nbit == 201) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 202) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 203) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 204) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 205) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 206) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 207) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 208) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 209) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 210) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 211) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 212) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 213) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 214) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 215) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 216) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 217) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 218) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 219) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 220) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 221) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 222) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 223) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 224) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 225) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 226) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 227) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 228) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 229) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 230) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 231) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 232) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 233) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 234) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 235) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 236) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 237) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 238) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 239) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 240) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}

			if (nbit == 241) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 242) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 243) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 244) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}

			if (nbit == 245) {
				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 246) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 247) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 248) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 249) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 250) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 251) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 252) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 253) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}
			if (nbit == 254) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 255) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}
			}
			if (nbit == 256) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r [%s] (%d bit) ", keys[i].GetBase16().c_str(), keys[i].GetBitLength());
				}

			}


		}

		if (rekey == 54) {
			string initial = seed;
			string str = initial;
			string last;
			for (int i = 0; i < 1000000000; i++) {
				last = str;
				str = increment(last);

				compare(last, str);
				string input = str;
				string nos = sha256(input);
				char* cstr = &nos[0];
				keys[i].SetBase16(cstr);
				if (diz == 0) {
					printf("\r [%s] ", str.c_str());
				}
				if (diz == 1) {
					printf("\r [%s] [%s] ", str.c_str(), keys[i].GetBase16().c_str());
				}

			}
		}
		if (rekey == 55) {
			int N = nbit;
			char str[]{ "!#$%&'()*+,-./:;<=>?@[\]^_`{|}~" };
			int strN = 31; // индекс последнего элемента в массиве
			//srand(time(NULL)); //инициализируем генератор случайных чисел
			char* pass = new char[N + 1]; //выдел€ем пам€ть дл€ строки парол€
			for (int i = 0; i < N; i++)
			{
				pass[i] = str[rand() % strN]; //вставл€ем случайный символ
			}
			pass[N] = 0; //записываем в конец строки признак конца строки
			string input = pass;
			string nos = sha256(input);
			char* cstr = &nos[0];
			keys[i].SetBase16(cstr);
			if (diz == 0) {
				printf("\r [%s] ", pass);
			}
			if (diz == 1) {
				printf("\r [%s] [%s] ", pass, keys[i].GetBase16().c_str());
			}

		}

		if (rekey == 56) {

			char* gyg = &seed[0];

			char* fun = &zez[0];
			this->rangeStart1.SetBase16(gyg);
			this->rangeEnd1.SetBase16(fun);



			this->rangeDiff2.Set(&this->rangeEnd1);
			this->rangeDiff2.Sub(&this->rangeStart1);

			this->rangeDiff3.Set(&this->rangeStart1);


			int tuk = rangeDiff2.GetBitLength();
			int br = 1 + rand() % tuk;

			if (br == 1) {
				int N = 1;

				char str[]{ "0123" };
				int strN = 4;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 2) {
				int N = 1;
				char str[]{ "4567" };
				int strN = 4;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;

				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 3) {
				int N = 1;

				char str[]{ "89ab" };
				int strN = 4;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 4) {
				int N = 1;
				char str[]{ "cdef" };
				int strN = 4;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;

				std::stringstream ss;
				ss << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 5) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 6) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 7) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;
				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 8) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 1;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 9) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 10) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 11) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 12) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 2;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 13) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 14) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 15) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 16) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 3;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 17) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 18) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 19) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 20) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 4;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 21) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 22) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 23) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 24) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 5;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 25) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 26) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 27) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 28) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 6;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 29) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 30) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 31) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 32) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 7;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 33) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 34) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 35) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 36) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 8;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 37) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 38) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 39) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 40) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 9;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 41) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 42) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 43) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 44) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 10;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 45) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 46) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 47) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 48) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 11;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}

			if (br == 49) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 50) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 51) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 52) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 12;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 53) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 54) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 55) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 56) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 13;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 57) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 58) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 59) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 60) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 14;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 61) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 62) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 63) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 64) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 15;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 65) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 66) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 67) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 68) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 16;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 69) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 70) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 71) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 72) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 17;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 73) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 74) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 75) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 76) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 18;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 77) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 78) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 79) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 80) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 19;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 81) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 82) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 83) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 84) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 20;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 85) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 86) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 87) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 88) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 21;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 89) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 90) {
				int N2 = 4;
				char str2[]{ "4567" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 91) {
				int N2 = 4;
				char str2[]{ "89ab" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 92) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 22;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 93) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 94) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 95) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 96) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 23;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}

			if (br == 97) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 98) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 99) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 100) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 24;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 101) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 102) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 103) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 104) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 25;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 105) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 106) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 107) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 108) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 26;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 109) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 110) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 111) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 112) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 27;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 113) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 114) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 115) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 116) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 28;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 117) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 118) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 119) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 120) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 29;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 121) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 122) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 123) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 124) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 30;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 125) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 126) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 127) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 128) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 31;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 129) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 130) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 131) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 132) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 32;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 133) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 134) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 135) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 136) {
				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 33;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 137) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 138) {
				int N2 = 4;
				char str2[]{ "4567" };
				int strN2 = 1;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 139) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 140) {
				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 34;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 141) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 142) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 143) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 144) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 35;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 145) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 146) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 147) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 148) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 36;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 149) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 150) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 151) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 152) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 37;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 153) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 154) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 155) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 156) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 38;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 157) {
				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 158) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 159) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 160) {
				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 39;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 161) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 162) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 163) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 164) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 40;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 165) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 166) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 167) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 168) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 41;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 169) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
			if (br == 170) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 171) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 172) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 42;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 173) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 174) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 175) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 176) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 43;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 177) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 178) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 179) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 180) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 44;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 181) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 182) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 183) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 184) {
				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 45;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 185) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 186) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 187) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 188) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 46;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 189) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 190) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 191) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 192) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 47;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 193) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 194) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 195) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 196) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 48;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 197) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 198) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 199) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 200) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 49;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 201) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 202) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 203) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 204) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 50;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 205) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 206) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 207) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 208) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 51;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 209) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 210) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 211) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 212) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 52;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 213) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 214) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 215) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 216) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 53;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 217) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 218) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 219) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 220) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 54;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 221) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 222) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 223) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 224) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 55;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 225) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 226) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 227) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 228) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 56;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 229) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 230) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 231) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 232) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 57;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 233) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 234) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 235) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 236) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 58;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 237) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 238) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 239) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 240) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 59;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 241) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 242) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 243) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 244) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 60;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 245) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 246) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 247) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 248) {

				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 61;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 249) {

				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;

				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 250) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 251) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Set(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 252) {
				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 62;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 253) {
				int N2 = 1;
				char str2[]{ "0123" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 254) {
				int N2 = 1;
				char str2[]{ "4567" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 255) {
				int N2 = 1;
				char str2[]{ "89ab" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}
			}
			if (br == 256) {
				int N2 = 1;
				char str2[]{ "cdef" };
				int strN2 = 4;
				char* pass2 = new char[N2 + 1];
				for (int i = 0; i < N2; i++)
				{
					pass2[i] = str2[rand() % strN2];
				}
				pass2[N2] = 0;

				int N = 63;
				char str[]{ "0123456789abcdef" };
				int strN = 16;
				char* pass = new char[N + 1];
				for (int i = 0; i < N; i++)
				{
					pass[i] = str[rand() % strN];
				}
				pass[N] = 0;
				std::stringstream ss;
				ss << pass2 << pass;
				std::string input = ss.str();
				char* cstr = &input[0];
				key22.SetBase16(cstr);
				this->rangeDiff3.Add(&key22);
				keys[i].Set(&rangeDiff3);
				if (diz == 0) {
					printf("\r (%d bit) ", keys[i].GetBitLength());
				}
				if (diz == 1) {
					printf("\r (%d bit) [%s] ", keys[i].GetBitLength(), keys[i].GetBase16().c_str());
				}

			}
		}
		
		


		Int k(keys + i);
		// Starting key is at the middle of the group
		k.Add((uint64_t)(groupSize / 2));
		p[i] = secp->ComputePublicKey(&k);
		//if (startPubKeySpecified)
		//	p[i] = secp->AddDirect(p[i], startPubKey);
	}

}

void LostCoins::FindKeyGPU(TH_PARAM *ph)
{

	bool ok = true;

#ifdef WITHGPU

	// Global init
	int thId = ph->threadId;
	GPUEngine g(ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, (rekey != 0),
		BLOOM_N, bloom->get_bits(), bloom->get_hashes(), bloom->get_bf(), DATA, TOTAL_ADDR);
	int nbThread = g.GetNbThread();
	Point *p = new Point[nbThread];
	Int *keys = new Int[nbThread];
	vector<ITEM> found;
	printf("  GPU         : %s\n\n", g.deviceName.c_str());
	counters[thId] = 0;

	getGPUStartingKeys(thId, g.GetGroupSize(), nbThread, keys, p);
	g.SetSearchMode(searchMode);
	g.SetSearchType(searchType);

	getGPUStartingKeys(thId, g.GetGroupSize(), nbThread, keys, p);
	ok = g.SetKeys(p);
	ph->rekeyRequest = false;

	ph->hasStarted = true;

	// GPU Thread
	while (ok && !endOfSearch) {

		if (ph->rekeyRequest) {
			getGPUStartingKeys(thId, g.GetGroupSize(), nbThread, keys, p);
			ok = g.SetKeys(p);
			ph->rekeyRequest = false;
		}

		// Call kernel
		ok = g.Launch(found, false);

		for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {

			ITEM it = found[i];
			//checkAddr(it.hash, keys[it.thId], it.incr, it.endo, it.mode);
			string addr = secp->GetAddress(searchType, it.mode, it.hash);
			if (checkPrivKey(addr, keys[it.thId], it.incr, it.endo, it.mode)) {
				nbFoundKey++;
			}

		}

		if (ok) {
			for (int i = 0; i < nbThread; i++) {
				keys[i].Add((uint64_t)STEP_SIZE);	
			}
			counters[thId] += 6ULL * STEP_SIZE * nbThread; // Point +  endo1 + endo2 + symetrics
		} 
		//ok = g.ClearOutBuffer();
	}
	delete[] keys;
	delete[] p;

#else
	ph->hasStarted = true;
	printf("GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif

	ph->isRunning = false;

}

// ----------------------------------------------------------------------------

bool LostCoins::isAlive(TH_PARAM *p)
{

	bool isAlive = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		isAlive = isAlive && p[i].isRunning;

	return isAlive;

}

// ----------------------------------------------------------------------------

bool LostCoins::hasStarted(TH_PARAM *p)
{

	bool hasStarted = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		hasStarted = hasStarted && p[i].hasStarted;

	return hasStarted;

}

// ----------------------------------------------------------------------------

void LostCoins::rekeyRequest(TH_PARAM *p)
{

	bool hasStarted = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		p[i].rekeyRequest = true;

}

// ----------------------------------------------------------------------------

uint64_t LostCoins::getGPUCount()
{

	uint64_t count = 0;
	for (int i = 0; i < nbGPUThread; i++)
		count += counters[0x80L + i];
	return count;

}

uint64_t LostCoins::getCPUCount()
{

	uint64_t count = 0;
	for (int i = 0; i < nbCPUThread; i++)
		count += counters[i];
	return count;

}

// ----------------------------------------------------------------------------

void LostCoins::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{
	
	double t0;
	double t1;
	endOfSearch = false;
	nbCPUThread = nbThread;
	nbGPUThread = (useGpu ? (int)gpuId.size() : 0);
	nbFoundKey = 0;

	memset(counters, 0, sizeof(counters));

	//printf("Number of CPU thread: %d\n\n", nbCPUThread);

	TH_PARAM *params = (TH_PARAM *)malloc((nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));
	memset(params, 0, (nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));

	// Launch CPU threads
	for (int i = 0; i < nbCPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = i;
		params[i].isRunning = true;

#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKey, (void *)(params + i), 0, &thread_id);
		ghMutex = CreateMutex(NULL, FALSE, NULL);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKey, (void *)(params + i));
		ghMutex = PTHREAD_MUTEX_INITIALIZER;
#endif
	}

	// Launch GPU threads
	for (int i = 0; i < nbGPUThread; i++) {
		params[nbCPUThread + i].obj = this;
		params[nbCPUThread + i].threadId = 0x80L + i;
		params[nbCPUThread + i].isRunning = true;
		params[nbCPUThread + i].gpuId = gpuId[i];
		params[nbCPUThread + i].gridSizeX = gridSize[2 * i];
		params[nbCPUThread + i].gridSizeY = gridSize[2 * i + 1];
#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyGPU, (void *)(params + (nbCPUThread + i)), 0, &thread_id);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyGPU, (void *)(params + (nbCPUThread + i)));
#endif
	}

#ifndef WIN64
	setvbuf(stdout, NULL, _IONBF, 0);
#endif

	uint64_t lastCount = 0;
	uint64_t gpuCount = 0;
	uint64_t lastGPUCount = 0;

	// Key rate smoothing filter
#define FILTER_SIZE 8
	double lastkeyRate[FILTER_SIZE];
	double lastGpukeyRate[FILTER_SIZE];
	uint32_t filterPos = 0;

	double keyRate = 0.0;
	double gpuKeyRate = 0.0;
	char timeStr[256];

	memset(lastkeyRate, 0, sizeof(lastkeyRate));
	memset(lastGpukeyRate, 0, sizeof(lastkeyRate));

	// Wait that all threads have started
	// Wait that all threads have started
	while (!hasStarted(params)) {
		Timer::SleepMillis(500);
	}

	// Reset timer
	Timer::Init();
	t0 = Timer::get_tick();
	startTime = t0;

	while (isAlive(params)) {

		int delay = 2000;
		while (isAlive(params) && delay > 0) {
			Timer::SleepMillis(500);
			delay -= 500;
		}
		
		gpuCount = getGPUCount();
		uint64_t count = getCPUCount() + gpuCount;

		t1 = Timer::get_tick();
		keyRate = (double)(count - lastCount) / (t1 - t0);
		gpuKeyRate = (double)(gpuCount - lastGPUCount) / (t1 - t0);
		lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
		lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
		filterPos++;

		// KeyRate smoothing
		double avgKeyRate = 0.0;
		double avgGpuKeyRate = 0.0;
		uint32_t nbSample;
		for (nbSample = 0; (nbSample < FILTER_SIZE) && (nbSample < filterPos); nbSample++) {
			avgKeyRate += lastkeyRate[nbSample];
			avgGpuKeyRate += lastGpukeyRate[nbSample];
		}
		avgKeyRate /= (double)(nbSample);
		avgGpuKeyRate /= (double)(nbSample);
		if (nbFoundKey > maxFound) {
			printf(" Exceeded message limit %d Found adreses. \n For more messages use -m 1000 (-m 10000000)  \n\n\n ", maxFound);
			exit(1);
		}
		
		if (diz == 0) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r                                                   [%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					avgKeyRate / 1000000.0,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}
		}
		if (diz == 1) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r                                                                                      [%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					avgKeyRate / 1000000.0,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}
		}
		if (diz > 1) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r [%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [T: %s] [F: %d]  ",
					toTimeStr(t1, timeStr),
					avgKeyRate / 1000000.0,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str(),
					nbFoundKey);
			}
		}
		if (rekey == 0) {
			if ((count - lastRekey) > (1 * 1)) {
				// Rekey request
				rekeyRequest(params);
				lastRekey = count;
			}
		}
		if (rekey == 1) {
			if((count - lastRekey) > (1 * 1)) {
				// Rekey request
				rekeyRequest(params);
				lastRekey = count;
			}
		}
		if (rekey == 2) {
			if ((count - lastRekey) > (1 * 50000000000)) {
				// Rekey request
				rekeyRequest(params);
				lastRekey = count;
			}
		}
		if (rekey == 3) {
			if ((count - lastRekey) > (1 * 100000000000)) {
				// Rekey request
				rekeyRequest(params);
				lastRekey = count;
			}
		}

		if (rekey > 3) {
			if ((count - lastRekey) > (1 * 1)) {
				// Rekey request
				rekeyRequest(params);
				lastRekey = count;
			}
		}

		lastCount = count;
		lastGPUCount = gpuCount;
		t0 = t1;
		endOfSearch = should_exit;
	}
	
	free(params);

}

// ----------------------------------------------------------------------------

string LostCoins::GetHex(vector<unsigned char> &buffer)
{
	string ret;

	char tmp[128];
	for (int i = 0; i < (int)buffer.size(); i++) {
		sprintf(tmp, "%02X", buffer[i]);
		ret.append(tmp);
	}
	return ret;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

int LostCoins::CheckBloomBinary(const uint8_t *hash)
{
	if (bloom->check(hash, 20) > 0) {
		uint8_t* temp_read;
		uint64_t half, min, max, current; //, current_offset
		int64_t rcmp;
		int32_t r = 0;
		min = 0;
		current = 0;
		max = TOTAL_ADDR;
		half = TOTAL_ADDR;
		while (!r && half >= 1) {
			half = (max - min) / 2;
			temp_read = DATA + ((current + half) * 20);
			rcmp = memcmp(hash, temp_read, 20);
			if (rcmp == 0) {
				r = 1;  //Found!!
			}
			else {
				if (rcmp < 0) { //data < temp_read
					max = (max - half);
				}
				else { // data > temp_read
					min = (min + half);
				}
				current = min;
			}
		}
		return r;
	}
	return 0;
}

std::string LostCoins::formatThousands(uint64_t x)
{
	char buf[32] = "";

	sprintf(buf, "%llu", x);

	std::string s(buf);

	int len = (int)s.length();

	int numCommas = (len - 1) / 3;

	if (numCommas == 0) {
		return s;
	}

	std::string result = "";

	int count = ((len % 3) == 0) ? 0 : (3 - (len % 3));

	for (int i = 0; i < len; i++) {
		result += s[i];

		if (count++ == 2 && i < len - 1) {
			result += ",";
			count = 0;
		}
	}
	return result;
}

char* LostCoins::toTimeStr(int sec, char* timeStr)
{
	int h, m, s;
	h = (sec / 3600);
	m = (sec - (3600 * h)) / 60;
	s = (sec - (3600 * h) - (m * 60));
	sprintf(timeStr, "%0*d:%0*d:%0*d", 2, h, 2, m, 2, s);
	return (char*)timeStr;
}


