Muhammad Ghanayem, ID: 207965922, email : mohammadga@campus.technion.ac.il
Eman Bsoul, ID: 318584919, email: eman.bsoul@campus.technion.ac.il

in order to obtain the .so file run the following: " make project.test "in the directory
<pindir>/source/tools/SimpleExamples with those files located there:
1. makefile
2. makfile.rules
3. project.cpp

a new directory will be created named "obj-intel64", you will find the project.so file there.

the run commands are:
1. <pindir>/pin -t project.so -prof -- ./test in 
2. <pindi>/pin -t project.so -opt -- ./test in
before running in opt mode you should have profiling.

the format of the count.csv file is the following:

Routine Name, Routine Address, Instruction Count, Call Count, Is Routine Recursive? , Dominate Caller address ,Is Candidate for inlining?

we identify candidates for inlining using the "is candidate for inline?" field and also if the routine is not recursive using the "Is Routine Recursive?" field.
the .csv file is already reordered by the functions with the highest amount of instructions on top and we choose routines who answer the criteria from the 
beginning of the .csv file.																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																					
																																																				