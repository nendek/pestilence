sh scripts/create_dir.sh
echo "execute check script"
sh scripts/check.sh
echo ""
echo "execute virus"
./death
echo "check if files are well infected"
sh scripts/check.sh
echo ""
echo "copy /tmp/test/python as infected in current directory"
cp /tmp/test/python infected
echo "recreate clean tests directories"
sh scripts/create_dir.sh
echo ""
echo "check directories are clean"
sh scripts/check.sh
echo "execute infected"
./infected
echo "check reinfection of the directories"
sh scripts/check.sh
