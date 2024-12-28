if [[ "$1" == "virus" ]];then
	echo '';
else
	grep $1;
fi;
