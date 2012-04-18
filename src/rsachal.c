/*  2000.09.01     */
/*  CryptNET       */
/*  vab@dublin.ie  */

#include "rc5.h"


void print_help(void);
int run_tests(void);
int menu(int);
int launch_attack(int,int,int);


int main(int argc,char *argv[])
{
	int rslt = 0;
	unsigned int arg = 0;
	unsigned int verbose = 0;
	unsigned int test_mode = 0;
	unsigned int bits = 0;
	
	
	printf("RSA Labs Challenge Attack Client\n");

	printf("Executing local environment tests...");
	
	rslt = run_tests();
	if(rslt != 0)
	{
		printf("\n\nERROR:  Test routine failed for %dbit code.\n", rslt);
		
		return -1;
	}
	
	printf("   OK.\n");
	
	if(argc > 0)
	{
		for(arg=1;arg<argc;arg++)
		{
			if(argv[arg][0] == '-')
			{
				if(argv[arg][1] == '-')
				{
					if(strstr(argv[arg],"help") != NULL)
					{
						print_help();

						return 0;
					}
					else if(strstr(argv[arg],"version") != NULL)
					{
						printf("RSAChal Version 1.0.0\n");

						return 0;
					}
					else if(strstr(argv[arg],"test") != NULL)
					{
						test_mode = 1;
					}
					else
					{
						print_help();

						return 0;
					}
				}
				else if(argv[arg][1] == 'v')
				{
					verbose = 1;
				}
				else if(argv[arg][1] == 't')
				{
					test_mode = 1;
				}
				else
				{
					print_help();

					return 0;
				}
			}
			else
			{
				if(isdigit(argv[arg][0]))
				{
					bits = atoi(argv[arg]);
				}
				else
				{
					print_help();
					
					return 0;
				}
			}
		}
		if(bits == 0)
		{
			menu(verbose);
		}
		else
		{
			launch_attack(test_mode,bits,verbose);
		}
	}
	else
	{
		menu(verbose);
	}
	
	
	return 0;
}


/* This function prints out command line help */

void print_help(void)
{
	printf("Usage: rsachal (options) <bits>\n");
	printf("	-v Verbose Mode\n");
	printf("	-h This Help Text\n");
	printf("	-t Attack Test Challenge\n");
	printf("	--test Attack Test Challenge\n");
	printf("	--help This Help Text\n");
	printf("	--version Display Version Information\n");
	printf("	<bits> Numerical Value Representing Challenge To Attack\n");
	printf("	       (40|48|56|64|72|80|88|96|104|112|120|128)\n");
	printf("\n");

	return;
}


/* This function prints a menu that allows the user can select which 
   challenge they want to attack. */
   
int menu(int verbose)
{
	char cmd[5];
	
	
	printf("\n\n");
	printf("RSA Labs RC5 Challenges:\n");
	printf("\n");
	printf("1) 40bit RSA Challenge\t\t1t) 40bit Test RSA Challenge\n");
	printf("2) 48bit RSA Challenge\t\t2t) 48bit Test RSA Challenge\n");
	printf("3) 56bit RSA Challenge\t\t3t) 56bit Test RSA Challenge\n");
	printf("4) 64bit RSA Challenge\t\t4t) 64bit Test RSA Challenge\n");
	printf("5) 72bit RSA Challenge\t\t5t) 72bit Test RSA Challenge\n");
	printf("6) 80bit RSA Challenge\t\t6t) 80bit Test RSA Challenge\n");
	printf("7) 88bit RSA Challenge\t\t7t) 88bit Test RSA Challenge\n");
	printf("8) 96bit RSA Challenge\t\t8t) 96bit Test RSA Challenge\n");
	printf("9) 104bit RSA Challenge\t\t9t) 104bit Test RSA Challenge\n");
	printf("10) 112bit RSA Challenge\t10t) 112bit Test RSA Challenge\n");
	printf("11) 120bit RSA Challenge\t11t) 120bit Test RSA Challenge\n");
	printf("12) 128bit RSA Challenge\t12t) 128bit Test RSA Challenge\n");
	printf("\n");
	printf("Please Select Challenge:  ");
	
	memset(cmd,0x00,5);
	fgets(cmd,4,stdin);
		
	if(strncmp("12t",cmd,3) == 0)
	{
		launch_attack(1,128,verbose);
	}
	else if(strncmp("12",cmd,2) == 0)
	{
		launch_attack(0,128,verbose);
	}
	else if(strncmp("11t",cmd,3) == 0)
	{
		launch_attack(1,120,verbose);
	}
	else if(strncmp("11",cmd,2) == 0)
	{
		launch_attack(0,120,verbose);
	}
	else if(strncmp("10t",cmd,3) == 0)
	{
		launch_attack(1,112,verbose);
	}
	else if(strncmp("10",cmd,2) == 0)
	{
		launch_attack(0,112,verbose);
	}
	else if(strncmp("9t",cmd,2) == 0)
	{
		launch_attack(1,104,verbose);
	}
	else if(strncmp("9",cmd,1) == 0)
	{
		launch_attack(0,104,verbose);
	}
	else if(strncmp("8t",cmd,2) == 0)
	{
		launch_attack(1,96,verbose);
	}
	else if(strncmp("8",cmd,1) == 0)
	{
		launch_attack(0,96,verbose);
	}
	else if(strncmp("7t",cmd,2) == 0)
	{
		launch_attack(1,88,verbose);
	}
	else if(strncmp("7",cmd,1) == 0)
	{
		launch_attack(0,88,verbose);
	}
	else if(strncmp("6t",cmd,2) == 0)
	{
		launch_attack(1,80,verbose);
	}
	else if(strncmp("6",cmd,1) == 0)
	{
		launch_attack(0,80,verbose);
	}
	else if(strncmp("5t",cmd,2) == 0)
	{
		launch_attack(1,72,verbose);
	}
	else if(strncmp("5",cmd,1) == 0)
	{
		launch_attack(0,72,verbose);
	}
	else if(strncmp("4t",cmd,2) == 0)
	{
		launch_attack(1,64,verbose);
	}
	else if(strncmp("4",cmd,1) == 0)
	{
		launch_attack(0,64,verbose);
	}
	else if(strncmp("3t",cmd,2) == 0)
	{
		launch_attack(1,56,verbose);
	}
	else if(strncmp("3",cmd,1) == 0)
	{
		launch_attack(0,56,verbose);
	}
	else if(strncmp("2t",cmd,2) == 0)
	{
		launch_attack(1,48,verbose);
	}
	else if(strncmp("2",cmd,1) == 0)
	{
		launch_attack(0,48,verbose);
	}
	else if(strncmp("1t",cmd,2) == 0)
	{
		launch_attack(1,40,verbose);
	}
	else if(strncmp("1",cmd,1) == 0)
	{
		launch_attack(0,40,verbose);
	}
	else
	{
		menu(verbose);
	}
	
	return 0;
}


/* This function calls test routines to make sure the code is performing
   proper and error free encryptions in this environment. */
   
int run_tests(void)
{
	if(test_40() != 0)
	{
		return 40;
	}
	if(test_48() != 0)
	{
		return 48;
	}
	if(test_56() != 0)
	{
		return 56;
	}
	if(test_64() != 0)
	{
		return 64;
	}
	if(test_72() != 0)
	{
		return 72;
	}
	if(test_80() != 0)
	{
		return 80;
	}
	if(test_88() != 0)
	{
		return 88;
	}
	if(test_96() != 0)
	{
		return 96;
	}
	if(test_104() != 0)
	{
		return 104;
	}
	if(test_112() != 0)
	{
		return 112;
	}
	if(test_120() != 0)
	{
		return 120;
	}
	if(test_128() != 0)
	{
		return 128;
	}

	return 0;
}

   
/* This function calls the attack routines to start attempting to solve one
   of the challenges. */

int launch_attack(int test_mode, int bits, int verbose)
{
	
	switch(bits)
	{
		case 40:
			if(test_mode)
				test_attack_40();
			else
				attack_40();
			break;
		case 48:
			if(test_mode)
				test_attack_48();
			else
				attack_48();
			break;
		case 56:
			if(test_mode)
				test_attack_56();
			else
				attack_56();
			break;
		case 64:
			if(test_mode)
				test_attack_64();
			else
				attack_64();
			break;
		case 72:
			if(test_mode)
				test_attack_72();
			else
				attack_72();
			break;
		case 80:
			if(test_mode)
				test_attack_80();
			else
				attack_80();
			break;
		case 88:
			if(test_mode)
				test_attack_88();
			else
				attack_88();
			break;
		case 96:
			if(test_mode)
				test_attack_96();
			else
				attack_96();
			break;
		case 104:
			if(test_mode)
				test_attack_104();
			else
				attack_104();
			break;
		case 112:
			if(test_mode)
				test_attack_112();
			else
				attack_112();
			break;
		case 120:
			if(test_mode)
				test_attack_120();
			else
				attack_120();
			break;
		case 128:
			if(test_mode)
				test_attack_128();
			else
				attack_128();
			break;
		default:
			menu(verbose);
			break;
	}

	return 0;
}
