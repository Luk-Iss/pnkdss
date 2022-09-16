# PNK DSS

Password: 
> 7T4W#+bjYY9wrS78

    openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt

    winpty openssl pkcs12 -inkey privateKey.key -in certificate.crt -export -out signcert.p12

    mvn clean compile package

    java -jar target/pnkDss-1.0-SNAPSHOT-one.jar src/main/resources/signcert.p12 src/main/resources/document.xml f n src/main/resources/pass.txt