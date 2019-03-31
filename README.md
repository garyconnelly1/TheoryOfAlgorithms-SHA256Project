# TheoryOfAlgorithms-SHA256Project
## Download and Run:

* Download this project by either downloading the .zip, or by typing "git clone https://github.com/garyconnelly1/TheoryOfAlgorithms-SHA256Project.git" into a command line.

* To run the program, simply type sha256 and press enter.
* You will be presented with three options;
  - Press 1 to hash a file.
  - Press 2 to enter a string to hash.
  - Press 3 to use the SHA256 login system.
  
## Sha256:
Sha256 is a hashing algorithm created by the NSA with the idea of creating hashes which are not computationally feasible to inverse. In order to learn how this algorithm worked, I followed the video series by Ian mcgloughlin as well as following the SHA government standard which can be found online.


## Additional features:
On top of what was completed through watching the video series, a few extra features were added. 

### Error checking:
There is error checking on all file inputs to ensure the file exists and can be used.

### Big Endian:
There are functions included that check if the system the program is running on is in Big Endian or Little Endian. The SHA256 algorithm requires Big Endian notation.

### User entered string:
The user has an option to enter their own string which can be hashed. This is done by creating a text file out of the users input, and passing that file to the algorithm.

### Login system:
This was added to showcase a possible use case of the sha256 algorithm. The users can create an "account" by supplying a username and password. The origional password the user enters is saved in a file called by the users username. This file is then hashed and output as a new file with a hashed version of the users password as its contents. 

The idea here was to create a login system also whereby the user enters their credentials, their password is hashed and checked against the already hashed password for that user. Unfortunately, I did not get time to finish implementing the login method. 

The basic idea of adding this feature, was to showcase that even if a melicious entity gained access to the machine and could read the hashed passwords, they would be useless as they are extremely difficult to inverse(to backwards engineer the hashed value to get the origional input). Obviously in a real system, the origional passwords would not be stored in a plain text file as they are in this case, this was just to make it easier to pass the file to the algorithm.

## Bugs:
While all of the hashed values are consistent(get the same hash value for the same input), they are not consistent with online versions of the sha256 algorithm. This obviously means there is a mistake somewhere in the algorithm that I couldn't find at the time of submission.

## Research:
Along with reading the standards for SHA and watching the video series, I also followed a course on tutorials point to get me up to cratch with C programming. https://www.tutorialspoint.com/cprogramming/ .

## Author:
Gary Connelly - G00336837.
