// Gary Connelly
#include <stdio.h>
#include <stdint.h>

void sha256();

// See Section 4.1.2 for definition. 
uint32_t sig0(uint32_t x);
uint32_t sig1(uint32_t x);

// See Section 3.2 for definitions.
uint32_t rotr(uint32_t n, uint32_t x);
uint32_t shr(uint32_t n, uint32_t x);


int main (int argc, char *argv[]){

  sha256();

  return 0;

}

void sha256(){

  uint32_t W[64];

  uint32_t a,b,c,d,e,f,g,h;



  uint32_t T1, T2;

  uint32_t H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
  };

  // For looping.
  int t;  
  
  // From page 22, W[t] = M[t] for 0 <= t <= 15.
  for(t = 0; t < 16; t++)
    W[t] = M[t];

  for(t = 16; t < 64; t++)
    sig_1(W[t-2]) + W[t-7] + sig_0(W[t-15]) + W[t-16];

  
  // Initialize a,b,c, ... ,h as per step 2, Page 22.
  a = H[0]; b = H[1]; c = H[2]; d = H[3];
  d = H[4]; e = H[5]; f = H[6]; f = H[7];

  // Step 3.
  for(t = 0; t < 64; t ++){

    T1 = h + SIG_1(e) + Ch(e,f,g) + K[t] + W[t];
    T2 = SIG_0(a) + Maj(a,b,c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;

  }// End for.

  
}

uint32_t sig0(uint32_t x){
  // See Sections 3.2 and 4.1.2 for definitions.
  return (rotr(7,x) ^ rotr(18, x) ^ shr(3,x));
}

uint32_t sig1(uint32_t x){
  // See Sections 3.2 and 4.1.2 for definitions.
  return (rotr(17,x) ^ rotr(19,x) ^ shr(10,x));
}

uint32_t rotr(uint32_t n, uint32_t x){
  // See Section 3.2 for definition.
  return (x >> n) | (x << (32-n));
}
uint32_t shr(uint32_t n, uint32_t x){
  return (x >> n);
}









