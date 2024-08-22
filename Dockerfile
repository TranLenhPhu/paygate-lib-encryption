FROM maven:3.9.8-eclipse-temurin-21 AS build

WORKDIR /app

COPY . .

RUN mvn clean package -DskipTests

RUN mvn install:install-file \
    -Dfile="/app/target/paygate-lib-encryption-1.0-SNAPSHOT.jar" \
    -DgroupId="vn.paygate" \
    -DartifactId="paygate-lib-encryption" \
    -Dversion="1.0-SNAPSHOT" \
    -Dpackaging="jar"
