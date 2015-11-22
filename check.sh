#!/bin/bash

MYDIR=$(dirname $0)
MYJAR=$MYDIR/target/serianalyzer-0.0.1-SNAPSHOT-jar-with-dependencies.jar
WHITELIST=$MYDIR/whitelist
JRE=/opt/oracle-jdk-bin-1.8.0.66/jre/lib/

set -e

ARTIFACT="$1"
WORKDIR=$(realpath $(pwd))


if [ ! -d "$ARTIFACT" ]
then
	if [ ! -f "$WORKDIR/pom.xml" ]
	then
		mvn org.apache.maven.plugins:maven-dependency-plugin:2.10:get -Dartifact=${ARTIFACT}:pom -DrepoUrl=http://repository.sonatype.org/content/repositories/central -Ddest=${WORKDIR}/pom.xml
	fi


	mvn org.apache.maven.plugins:maven-dependency-plugin:2.10:copy -Dartifact=${ARTIFACT}:jar -DrepoUrl=http://repository.sonatype.org/content/repositories/central -DoutputDirectory=$WORKDIR/jars/ || true

	echo ${@:2}
	mvn org.apache.maven.plugins:maven-dependency-plugin:2.10:copy-dependencies -DoutputDirectory=$WORKDIR/jars/ -DincludeScope=runtime -DrepoUrl=http://repository.sonatype.org/content/repositories/central ${@:2}

	TARGETS=$(ls $WORKDIR/jars/*.jar)
else
	TARGETS=$@
fi

echo "Running analysis"
echo java -Xmx8G -cp "$MYJAR" eu.agno3.tools.serianalyzer.Main --whitelist $WHITELIST -d -o state $JRE $TARGETS

java -Xmx8G -cp "$MYJAR" eu.agno3.tools.serianalyzer.Main --whitelist $WHITELIST -o state $JRE $TARGETS 2>&1 | tee analyze.log
