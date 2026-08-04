# Build stage
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app

# Pre-fetch Maven dependencies for layer caching
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build package
COPY src ./src
RUN mvn package -DskipTests -B

# Download Pyroscope Java agent (cached by Docker ADD)
ADD https://github.com/grafana/pyroscope-java/releases/download/v0.14.0/pyroscope.jar /app/pyroscope.jar

# Run stage
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
COPY --from=build /app/pyroscope.jar pyroscope.jar
EXPOSE 80
ENTRYPOINT ["java", "-javaagent:/app/pyroscope.jar", "-jar", "app.jar"]
