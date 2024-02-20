Name: Muhammad Ghanayem
ID : 207965922

how to compile and run the tool : 
1. copy ex1.cpp file into SimpleExamples in the pin directory. 
2. in SimpleExamples folder run "make ex1.test" in Terminal.
3. now a directory named obj-intel64 is created that includes the ex1.so file.
4. move ex1.so and the test file to the pin tool directory.
5. run in Terminal: time <pin dir>/pin -t ex1.so -- ./tst 
6. now rtn-output.csv is created which has the output of the pintool , in addition this will measure the time it took the tool to run.