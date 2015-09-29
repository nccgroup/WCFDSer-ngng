#!/usr/bin/env bash

rm -rf build/burp/
rm -rf bin/wcf.jar
javac -d build src/burp/*.java
jar cf bin/wcf.jar -C build burp
