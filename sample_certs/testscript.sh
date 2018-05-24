#!/bin/bash
INFILE="output.csv"
INPUTFILE="sample_input.csv"

if [ ! -f certcheck ]; then
    echo -e "certcheck executable NOT FOUND - Test Stopped - Check program naming\n"
    exit 1
fi
echo -e "Running certcheck with input file:$INPUTFILE"
./certcheck $INPUTFILE
echo -e "\n\ncertcheck finished, starting output checks"
if [ ! -f output.csv ]; then
    echo -e "output.csv NOT FOUND - Test Stopped - Check output file name\n"
    exit 1
fi

declare -A results
results[testone.crt,www.example.com]=0
results[testtwo.crt,www.mydomain.com]=1
results[testthree.crt,www.test.com]=0
results[testfour.crt,www.oldsite.com]=0
results[testfive.crt,www.unimelb.com]=0
results[testsix.crt,www.codetest.com]=0
results[testseven.crt,www.example.com]=1
results[testeight.crt,www.comp30023.com]=1
results[testnine.crt,www.certtest.com]=1
results[testten.crt,www.victoria.com]=1
results[testeleven.crt,freeca.com]=0
results[testtwo.crt,www.example.com]=0
results[testseven.crt,example.com]=0

while IFS=',' read -ra line || [[ -n "$line" ]]; do
    if [ ${results["${line[0]},${line[1]}"]} == ${line[2]} ] 
    then
        if [ ${line[2]} == "0" ] 
        then
            echo -e "${line[0]},${line[1]}:CertCheck=INVALID:TEST=PASS"
        else
            echo -e "${line[0]},${line[1]}:CertCheck=VALID:TEST=PASS"
        fi
        
    else
        if [ ${line[2]} == "0" ] 
        then
            echo -e "${line[0]},${line[1]}:CertCheck=INVALID:Actual=VALID:TEST=FAIL"
        else
            echo -e "${line[0]},${line[1]}:CertCheck=VALID:Actual=INVALID:TEST=FAIL"
        fi
        #echo -e "${line[0]},${line[1]}=FAIL"
    fi
    #echo -e 
    #for i in "${line[@]}"; do
    #    echo -e "value: $i\n"
    #done
done < "$INFILE"