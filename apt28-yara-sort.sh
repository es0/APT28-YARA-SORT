

echo "YARA APT28 MALWARE FAMILY SORTER"
echo " Sorts CORESHELL, X-Agent, XTunnel, etc..."

#rule_dir=$1
malware_dir=$1
list=(X-Agent CORESHELL XTunnel EVILTOSS BlackEnergy)
yara_rule_dir=$2
for i in ${list[@]}
do
	
	yara -p 20 -g -m $yara_rule_dir/rules/malware/APT_*.yar -r $malware_dir | grep "GRIZZLY-STEPPE" | grep "$i" | sort > APT_28-$i-Family_Samples.txt
	

	cat APT_28-$i-Family_Samples.txt | cut -d"]" -f3 > sample_dir.txt  	
	samples=sample_dir.txt
	while read -r sample
	do
		echo "\nFAMILY: $i"
		echo "$sample"	
		cp "$sample" APT28/Malware-Family/$i/
	done < "$samples"	
done


