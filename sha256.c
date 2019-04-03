// Gary Connelly - G00336837
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>



// From - esr.ibiblio.org/?p=5095
#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8 ) | ((x) << 24))
#define IS_BIG_ENDIAN (*(uint16_t *)"\0\xff" < 0x100) 
#define DATA_SIZE 1000
#define ERROR_MESSAGE "Invalid input, please try again! \n"
union msgblock{
  uint8_t e[64];
  uint32_t t[16];
  uint64_t s[8];

};

uint32_t Output[8]; // Declare array to allow for global access to the current hash.

enum status {READ, PAD0, PAD1, FINISH};

void sha256(FILE *file);
// =========================================== Added features.
void loginSystem();
void login();
void signUp();
int cfileexists(const char * filename);
void enterString();
// ========================================= End Added features.

int nextMsgBlock(FILE *file, union msgblock *M, enum status *S, uint64_t *noBits);


// See Section 4.1.2 for definition. 
uint32_t sig0(uint32_t x);
uint32_t sig1(uint32_t x);


uint32_t SIG0(uint32_t x);
uint32_t SIG1(uint32_t x);

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);
// See Section 3.2 for definitions.
uint32_t rotr(uint32_t n, uint32_t x);
uint32_t shr(uint32_t n, uint32_t x);

// Method to convert from Little Endian to Big Endian.
unsigned int LitToBigEndian(unsigned int x);

 // The K constants, defined in section 4.4.4.
  static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2


};

int main (int argc, char *argv[]){

 // login();

  FILE *file;

  char menuOption[DATA_SIZE]; // Store the current menu choice.

  /*
  Start Menu.
  */
  printf("Press 1 to hash a file:\n");
  printf("Press 2 to enter a string to hash:\n");
  printf("Press 3 to use a SHA256 login/registration system:\n");
  gets(menuOption);

 

  if(strcmp(menuOption, "1") == 0){ // If they chose one, get them to enter the name of the file to hash.
    printf("Enter the name of the file you wish to hash(include the extension eg. .txt)");
    gets(menuOption);

     // Open the file and send it to the hash algorithm.
   if((file = fopen(menuOption, "r"))!=NULL){
     sha256(file);  
   }
   else{ // If, for any reason this file cannot be opened.
     printf("Error occurred while opening file, please try again!");
   }

  
  
  fclose(file);

    
} // End if menuOption ==1. 
else if(strcmp(menuOption, "2") == 0){
    enterString(); // Send them to the enterString() method to handle the user input.
}
else if(strcmp(menuOption, "3") == 0){
  loginSystem(); // Send them to the loginSystem() method.
}else{// If they enter an option that is not 1, 2 or 3.
  printf(ERROR_MESSAGE);
}

  
  return 0;

}

void sha256(FILE *file){

  union msgblock M;

  uint64_t nobits = 0;

  enum status S = READ;

 
  
  // Message shedule (Section 6.2). 
  uint32_t W[64];
  // Working variables (Section 6.2).
  uint32_t a,b,c,d,e,f,g,h;
  // Two temporary variables (Section 6.2).
  uint32_t T1, T2;


  // The hash values (Section 6.2).
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
  
 // uint32_t M[16]  = {0,0,0,0,0,0,0,0};

  // For looping.
  int t,i;  
  
  while(nextMsgBlock(file, &M, &S, &nobits)){
  
  // From page 22, W[t] = M[t] for 0 <= t <= 15.
  for(t = 0; t < 16; t++){
   // if(IS_BIG_ENDIAN){
       W[t] = M.t[t];
   // }else{
     // W[t] = SWAP_UINT32(M.t[t]) ;
   // }
   
  }
    

  for(t = 16; t < 64; t++)
    W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];

  
  // Initialize a,b,c, ... ,h as per step 2, Page 22.
  a = H[0]; b = H[1]; c = H[2]; d = H[3];
  d = H[4]; e = H[5]; f = H[6]; f = H[7];

  // Step 3.
  for(t = 0; t < 64; t ++){

    T1 = h + SIG1(e) + Ch(e,f,g) + K[t] + W[t];
    T2 = SIG0(a) + Maj(a,b,c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;

  }// End while.

  // Step 4.
  H[0] = a + H[0];
  H[1] = b + H[1];
  H[2] = c + H[2];
  H[3] = d + H[3];
  H[4] = e + H[4];
  H[5] = f + H[5];
  H[6] = g + H[6];
  H[7] = h + H[7];
    

 }// End while.
  // Check if it is already Big Endian.
  if(IS_BIG_ENDIAN){
    printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]);
    for(t = 0; t < 8; t++){
        Output[t] =H[t];
    }
   }else{
    printf("Big Endian: %08x %08x %08x %08x %08x %08x %08x %08x\n",

      SWAP_UINT32(H[0]),
      SWAP_UINT32(H[1]),
      SWAP_UINT32(H[2]),
      SWAP_UINT32(H[3]),
      SWAP_UINT32(H[4]),
      SWAP_UINT32(H[5]),
      SWAP_UINT32(H[6]),
      SWAP_UINT32(H[7])
    );

    for(t = 0; t < 8; t++){
        Output[t] =SWAP_UINT32(H[t]); // Populate the global Output[] array to have global access to the hash values.
    }
  
   }// End if else (IS_BIG_ENDIAN).

 

}// End sha. (Look up Big Endian and Little Endian.)

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



uint32_t SIG0(uint32_t x){
  return (rotr(2,x) ^ rotr(13,x) ^ rotr(22,x));
}
uint32_t SIG1(uint32_t x){
  return (rotr(6,x) ^ rotr(11,x) ^ (25,x));
}

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z){
  return ((x & y) ^ ((!x) & z));
}
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z){
  return ((x & y) ^ (x & z) ^ (y & z));
}

// Method definition for LitToBigEndian.
unsigned int LitToBigEndian(unsigned int x){
  return (((x >> 24) & 0x000000ff) | ((x >> 8) & 0x0000ff00) | ((x << 8) & 0x00ff0000) | ((x << 24) & 0xff000000));
}

// Message Block function here.
int nextMsgBlock(FILE *file, union msgblock * M, enum status *S, uint64_t *nobits){

  // The number of bytes we get from fread.
  uint64_t nobytes;

  //For looping.
  int i;

  // If we have finished all of the message blocks, then S should be FINISH.
  if(*S == FINISH)
    return 0;

  // Otherwise, check if we need another block full of padding.
  if(*S == PAD0 || *S == PAD1){
    // Set the first 56 bytes to all zero bits.
    for(i = 0; i < 56; i++)
      M->e[i] = 0x00;
    // Set the last 64 bits to the number of bits in the file( should be big-endian).
    M->s[7] = *nobits; 
    // Tell S we are finished.
    *S = FINISH;
    // If S was PAD1, then set the first bit of M to one.
    if(*S == PAD1)
      M->e[0] = 0x80;
    // Keep the loop in sha256 going for one more iteration.
    return 1;
  }// End if.

  // If we get down here, we havn't finished readong the file (S == READ).
  nobytes = fread(M->e, 1, 64, file);

  // Keep track of the number of bytes we've read.
  *nobits = *nobits + (nobytes * 8);
  
  // If we read less than 56 bits, we can put all padding in this message block.
  if(nobytes < 56){
    // Add the one bit, as per the standard.
    M->e[nobytes] = 0x80;

    // Add the zero bits until the last 64 bits.
    while(nobytes < 56){
      nobytes = nobytes + 1;
      M->e[nobytes] = 0x00;
    }//End while nobytes < 56
    // Append the file size in bits as an unsigned 64 bit int. (Should be Big Endian).
    M->e[7] = *nobits;
    // Tell S we are finished.
    *S = FINISH;
    // Otherwise, check if we can put some padding into this message block.
  }//End if nobytes < 56
  else if (nobytes < 64){
    // Tell S we need another message block, with padding but no one bit.
    *S = PAD0;
    // Put the one bit into the current block.
    M->e[nobytes] = 0x80;
    // Pad the rest of this block wth zero bits.
    while(nobytes < 64){
      nobytes = nobytes + 1;
      M->e[nobytes] = 0x00;
    }// End while nobytes < 64
   
  }// End else if nobytes < 64
  // Otherwise, check if we are just at the end of the file.
  else if(feof(file)){
    // Tell S that we need another message block with all the padding.
    *S = PAD1;
  }// End else if feof(file)
  
  // If we get this far, then return 1 so that the function is called again.
  return 1;
  
}// End nextMsgBlock






void enterString(){ // Alow the user to enter their own string to be hashed.

  char input[DATA_SIZE]; // To store the users input.
  FILE *filePointer; // Declare a pointer to the file we want the users input to be written to.
  

  printf("Enter the string you wish to hash:\n");
  gets(input);

  filePointer = fopen("input.txt", "w"); // Create the file.

  if(filePointer == NULL){ // If an error occurred creating the file.
    printf("Error writing the input to a file. Please try again.");
    exit(EXIT_FAILURE);
  }// End if filePointer == NULL.

  fputs(input, filePointer); // Write the users input to the file.

 

  fclose(filePointer); // Close the file.




 if((filePointer = fopen("input.txt", "r"))!=NULL){ // Open the same file, this time with read permissions.
     sha256(filePointer);  // Hash the file and display the answer to the user.
     
   }
   else{
     printf("Error occurred while opening file, please try again!");
   }

  
  
  fclose(filePointer); // Close the file.

}


void loginSystem(){ 
  /*
    This is to display a possible application of the SHA256 algorithm.

    The only purpose of this particular function, is to send the user to the right part of the program.
  */
   char menuOption[DATA_SIZE];

  printf("Press 1 to sign up. Press 2 to log in:\n");
  gets(menuOption);

  if(strcmp(menuOption, "1") == 0){
    signUp(); // Send the user to the signup() method.
  }else if(strcmp(menuOption, "2") == 0){
   // login(); Login method was incomplete, so it is commented out to prevent crashing the program.
  }
  else{
    printf(ERROR_MESSAGE);
  }
} // End loginSystem().

void signUp(){

  /*
  A method to simulate creating a user account, using the sha256 algorithm to hash the users password.
  */

 char *a[8]; // Declare array that stores the string values of the uint32_t[] in Output.

/*
Created 8 different temp variables to solve pointer issues.
*/
  char temp[8];
  char temp1[8];
  char temp2[8];
  char temp3[8];
  char temp4[8];
  char temp5[8];
  char temp6[8];
  char temp7[8];
  printf("================== Sign up ================== \n");

  char data[DATA_SIZE]; // To get data from the users.
  char userName[DATA_SIZE];
  char fileName[DATA_SIZE];
  FILE *filePointer;
  FILE *outFile;
  char hashFileName[DATA_SIZE];
  //char buffer[DATA_SIZE];

  printf("Enter a username: "); // Get the users username.
  gets(userName);

  strcat(userName, ".txt"); // Append the username to .txt to create a file for that user.
  if(cfileexists(userName)){ // Check if that username already exists by seeing if a file by the same name exists.
    printf("Username already exists, please try another one!");
    exit(EXIT_FAILURE);
  }else{
    filePointer = fopen(userName, "w"); // Point to the file with write permissions.

    if(filePointer == NULL){
      printf("Unable to create file. \n");
      exit(EXIT_FAILURE);
    }

    printf("Enter your password: "); // Get the user to enter a password.
    gets(data);

    fputs(data, filePointer); // Writeh the plain text password to the file.

    fclose(filePointer); // Close the file.


    // Try to hash that file.
    if((filePointer = fopen(userName, "r"))!=NULL){
     sha256(filePointer); // Create the hash value of the password.
     printf("OUTPUT ---> \n");
     // Check if it is already Big Endian.
     printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", Output[0],Output[1],Output[2],Output[3],Output[4],Output[5],Output[6],Output[7]);
     strcpy(hashFileName, "hash"); // Prefix the word "hash" to the start of the files name.
     strcat(hashFileName, userName); // Create a nother file with the hash of the users password, called hash*userName*.txt.
    


      /*
      Had to copy elements to the array like this because elements were getting overwridden by the last element.
      */
     sprintf(temp, "%08x", Output[0]); // Convert the uint32_t into a hexadecimal string. https://stackoverflow.com/questions/3464194/how-can-i-convert-an-integer-to-a-hexadecimal-string-in-c
     a[0] = temp;
     printf("HEX %s\n", a[0]);

     sprintf(temp1, "%08x", Output[1]);
     a[1] = temp1;
     printf("HEX %s\n", a[1]);

      sprintf(temp2, "%08x", Output[2]);
     a[2] = temp2;
     printf("HEX %s\n", a[2]);

      sprintf(temp3, "%08x", Output[3]);
     a[3] = temp3;
     printf("HEX %s\n", a[3]);

      sprintf(temp4, "%08x", Output[4]);
     a[4] = temp4;
     printf("HEX %s\n", a[4]);

      sprintf(temp5, "%08x", Output[5]);
     a[5] = temp5;
     printf("HEX %s\n", a[5]);

      sprintf(temp6, "%08x", Output[6]);
     a[6] = temp6;
     printf("HEX %s\n", a[6]);

      sprintf(temp7, "%08x", Output[7]);
     a[7] = temp7;
     printf("HEX %s\n", a[7]);






/*
Also had to write elements to the file like this because elements were getting iverwritten.
*/

    printf("Here: %s\n", a[0]); // Print out the first element of a to make sure is wasn't overridden by the last element.
     outFile = fopen(hashFileName, "a"); // Write the hashed password to the newly created file.
     
     fputs(a[0], outFile);

     fputs(a[1], outFile);

     fputs(a[2], outFile);

     fputs(a[3], outFile);

     fputs(a[4], outFile);

     fputs(a[5], outFile);

     fputs(a[6], outFile);

     fputs(a[7], outFile);



    
     fclose(outFile); // Close the file.
    
  
   }
   else{
     printf("Error occurred while opening file, please try again!");
   }

  
  
   fclose(filePointer); // Close the file.
  }// End else.

   printf("Password created and stored! \n"); 

}

/*
Didn/t get this method finished so I left it out of menu options.

This file was added near enough to the deadline, so it is incomplete and there is no doubt a lot of bugs in it. 
The idea for this method, was to have the user enter a username and password. Search the file system for the file with their username preceeded by the word "hash",
if such a file exists, read it in and save its contents. Hash the password the user just entered to login by saving it to the Output global variable. Convert that
output variable to a string representation of the hexidecimal number. Finally compare that string, with the string read in from the users file. If they match, then 
the user is validated and just see a "Welcome to app" message. If not, then the password is incorrect.
*/
void login(){
  printf("================== Login ================== \n");

  char data[DATA_SIZE];
  char name[DATA_SIZE];
  char userName[DATA_SIZE];
  char password[DATA_SIZE];
  char *a[8];

  /*
  Also created the temp array like this to get around the pointer issue.
  */
  char temp[8];
  char temp1[8];
  char temp2[8];
  char temp3[8];
  char temp4[8];
  char temp5[8];
  char temp6[8];
  char temp7[8];


  strcpy(name, "hash"); // The file we need to find has to begin with the word hash.
  

 char *result;
 char *result2;
 FILE *outFile;
 char hashFileName[DATA_SIZE];

  printf("Enter your username: ");
  gets(userName);
  strcat(userName, ".txt"); // Append ".txt" to the username so it can be searched in the file directory.

strcat(name,userName); // Append this username to "hash".
printf("name ---> %s\n", name);
strcat(hashFileName, "compare");
  

  if(cfileexists(name)){

    printf("Enter the password:\n");
    gets(data);
    strcat(password, name);

    strcat(password, "check.txt");



    outFile = fopen(password, "w");

    if(outFile == NULL){
      printf("Error writing the input to a file. Please try again.");
      exit(EXIT_FAILURE);
    }// End if filePointer == NULL.

  fputs(data, outFile);

 

  fclose(outFile);

 // sha256(filePointer);


 if((outFile = fopen(password, "r"))!=NULL){
     sha256(outFile);  
     
   }
   else{
     printf("Error occurred while opening file, please try again!");
   }

  
  
  fclose(outFile);
    
  }else{ // If the file doesnt exist, that means the username they entered doesn't exist.
    printf("User doesnt exist, please sign up to continue.\n");
    exit(EXIT_FAILURE);
  }

  strcat(hashFileName, password); // To give the resulting hashed file a dfferent name.
  

 


   // Get a handle on the hashed value
    sprintf(temp, "%08x", Output[0]);
     a[0] = temp;
     printf("HEX %s\n", a[0]);

     sprintf(temp1, "%08x", Output[1]);
     a[1] = temp1;
     printf("HEX %s\n", a[1]);

      sprintf(temp2, "%08x", Output[2]);
     a[2] = temp2;
     printf("HEX %s\n", a[2]);

      sprintf(temp3, "%08x", Output[3]);
     a[3] = temp3;
     printf("HEX %s\n", a[3]);

      sprintf(temp4, "%08x", Output[4]);
     a[4] = temp4;
     printf("HEX %s\n", a[4]);

      sprintf(temp5, "%08x", Output[5]);
     a[5] = temp5;
     printf("HEX %s\n", a[5]);

      sprintf(temp6, "%08x", Output[6]);
     a[6] = temp6;
     printf("HEX %s\n", a[6]);

      sprintf(temp7, "%08x", Output[7]);
     a[7] = temp7;
     printf("HEX %s\n", a[7]);


     // Write out thr resulting hash to a file:

      outFile = fopen(hashFileName, "a");
     
     fputs(a[0], outFile);

     fputs(a[1], outFile);

     fputs(a[2], outFile);

     fputs(a[3], outFile);

     fputs(a[4], outFile);

     fputs(a[5], outFile);

     fputs(a[6], outFile);

     fputs(a[7], outFile);



    
     fclose(outFile);
    




   

}

/*
 * Check if a file exist using fopen() function
 * return 1 if the file exist otherwise return 0
 */
int cfileexists(const char * filename){
//  printf("Youre userName: ---> %s\n", filename);   

 /* try to open file to read */
    FILE *file;
    if (file = fopen(filename, "r")){
        fclose(file);
        return 1;
    }
    return 0;
}




