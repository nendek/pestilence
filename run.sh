rm ./test/patched
rm ./test/test
make re
cp ./test/a.out ./test/test
./pestilence
mv ./test/test infected
cp ./test/a.out ./test/test
./infected
