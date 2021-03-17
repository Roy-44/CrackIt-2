# Crack It 2
Crack It is a multi process application that illustrates a password hacking using brute force technique.
One process generates a randomized plain password, encrypts it using a randomized key and sends the encrypted buffer to X decrypter processes by mqueues, the decrypter processes compete to decrypt the encrypted password by trying to guess the key.

Instructions:
-------------
1. run "sudo apt install libssl-dev" command.

2. run "sudo dpkg --install mta-utils-dev.deb" command.

3. Run "make" command.

4. There are two ways to use the app:

	a. Run "sudo ./launcher.out <num-of-decrypters> -n <decrypter-number-of-rounds>".
	
	b. Run manually the server using the command "sudo ./server.out" and then the decrypters using the command "./decrypter.out <decrypter-id> -n <decrypter-number-of-rounds>".

	* The flag "-n" and his value are optional.
	* When running the command "./decrypter.out <decrypter-id> -n <decrypter-number-of-rounds>" it's the user responsibility to use different ids to different decrypters.

5. It's possible to use the command "make clean" to clean the compilation outputs.

6. To change password len, change the define PLAIN_DATA_LEN at include.h.
