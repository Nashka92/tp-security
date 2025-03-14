FROM maven AS builder

WORKDIR /app

COPY pom.xml .

RUN mvn dependency:go-offline

COPY src ./src

RUN mvn package -DskipTests

FROM openjdk:22-oracle

WORKDIR /app

COPY --from=builder /app/target/spring-security-m2ibank-0.0.1-SNAPSHOT.jar .

EXPOSE 8090

ENTRYPOINT ["java", "-jar", "spring-security-m2ibank-0.0.1-SNAPSHOT.jar"]