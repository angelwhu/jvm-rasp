#!/usr/bin/env bash
# mvn clean package -DskipTests
cp ./target/jvm-rasp-1.0-SNAPSHOT-jar-with-dependencies.jar ./sandbox/module
pid=`ps aux | grep ddctf|grep -v grep|awk '{print $2}'`
echo ${pid}
cd ./sandbox/bin/
./sandbox.sh -p ${pid} -S
./sandbox.sh -p ${pid}
./sandbox.sh -p ${pid} -d "detect-rce-logger/rcedetect"
#./sandbox.sh -p ${pid} -d "system-block/blockSystemExec"
cd -
