#!/bin/sh

TAG="${1}"
if [ -z "${TAG}" ]
then
	exit 0
fi
for matrixname in enterprise ics mobile
do
	if [ ! -d "${matrixname}" ]
	then
		mkdir "${matrixname}"
		mkdir "${matrixname}/industry"
		mkdir "${matrixname}/region"
	fi
	for industryname in ".* food.*|.* meal.*|.* restaurant.*|.* hospitality.*|.* catering.*" ".* military.*|.* defen[cs]e.*|.* armed.*" ".* telco.*|.* telecom.*|.* carrier.*|.* phone.*" ".* servic.*|.* ISP.*|.* MSP.*|.* provid.*" ".* NGO.*|.* charit.*" ".* credit.*|.* financ.*|.* bank.*|.* trading.*|.* stocks.*|.* forex.*|.* payment.*" ".* bitcoin.*" ".* pharma.*|.* health.*" ".* teach.*|.* academi.*|.* school.*|.* universit.*|.* college.*" ".* govern.*" ".* energy.*|.* gas.*|.* petrol.*|.* oil.*" ".* water.*|.* gas.*|.* electric.*|.* utilit.*" ".* transport.*|.* rail.*|.* train.*|.* car.*|.* vehicle.*|.* road.*|.* automotiv.*|.* boat.*|.* tanker.*|.* plane.*|.* airport.*" ".* retail.*|.* commerc.*" ".* cloud.*|.* devops.*" ".* factory.*|.* manufactur.*" ".* chemic.*"
	do
		industryreportname="$(printf "${industryname}" | tr -d ".*| \[\]")"
		if [ ! -d "${matrixname}/industry/${industryreportname}" ]
		then
			mkdir "${matrixname}/industry/${industryreportname}"
		fi
		threat-crank/threat-crank.py -i "${industryname}" -A "https://raw.githubusercontent.com/mitre/cti/${TAG}/${matrixname}-attack/${matrixname}-attack.json" >"${matrixname}/industry/${industryreportname}/${TAG}.md"
		threat-crank/threat-crank.py -G unified -i "${industryname}" -A "https://raw.githubusercontent.com/mitre/cti/${TAG}/${matrixname}-attack/${matrixname}-attack.json" >"${matrixname}/industry/${industryreportname}/${TAG}.tsv"
		cp "${matrixname}/industry/${industryreportname}/${TAG}.md" "${matrixname}/industry/${industryreportname}/current.md"
		cp "${matrixname}/industry/${industryreportname}/${TAG}.tsv" "${matrixname}/industry/${industryreportname}/current.tsv"
		[ -z "${DEBUG}" ] && git add "${matrixname}/industry/${industryreportname}/*.md" "${matrixname}/industry/${industryreportname}/*.tsv"
	done
	for regionname in ".* norw.*|.* swed.*|.* finland.*|.* denmark.*|.* scandinav.*" ".* britain.*|.* united kingdom.*|.* england.*|.* scotland.*|.* ireland.*|.* wales.*" ".* saud.*|.* ksa.*" ".* qatar.*" ".* iran.*" ".* iraq.*" ".* china.*|.* chinese.*" ".* israel.*" ".* russia.*" ".* ukrain.*" ".* franc.*" ".* german.*" ".* europe.*" ".* america.*|.* united states.*" ".* canada.*" ".* india.*" ".* brazil.*" ".* australia.*" ".* zealand.*" ".* singapore.*" ".* pakistan.*" ".* poland.*|.* polska.*|.* polish.*"
	do
		regionreportname="$(printf "${regionname}" | tr -d ".*| \[\]")"
		if [ ! -d "${matrixname}/region/${regionreportname}" ]
		then
			mkdir "${matrixname}/region/${regionreportname}"
		fi
		threat-crank/threat-crank.py -r "${regionname}" -A "https://raw.githubusercontent.com/mitre/cti/${TAG}/${matrixname}-attack/${matrixname}-attack.json" >"${matrixname}/region/${regionreportname}/${TAG}.md"
		threat-crank/threat-crank.py -G unified -r "${regionname}" -A "https://raw.githubusercontent.com/mitre/cti/${TAG}/${matrixname}-attack/${matrixname}-attack.json" >"${matrixname}/region/${regionreportname}/${TAG}.tsv"
		cp "${matrixname}/region/${regionreportname}/${TAG}.md" "${matrixname}/region/${regionreportname}/current.md"
		cp "${matrixname}/region/${regionreportname}/${TAG}.tsv" "${matrixname}/region/${regionreportname}/current.tsv"
		[ -z "${DEBUG}" ] && git add "${matrixname}/region/${regionreportname}/*.md" "${matrixname}/region/${regionreportname}/*.tsv"
	done
done
[ -z "${DEBUG}" ] && git commit -m "Updated ${TAG}"
