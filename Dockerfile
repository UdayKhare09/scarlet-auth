# Build stage
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests

# Download Pyroscope Java agent
FROM eclipse-temurin:21-jre AS pyroscope-downloader
RUN apt-get update && apt-get install -y curl && \
    curl -Lo /pyroscope.jar \
    https://github.com/grafana/pyroscope-java/releases/download/v0.14.0/pyroscope.jar

# Run stage
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
COPY --from=pyroscope-downloader /pyroscope.jar pyroscope.jar
EXPOSE 80
ENTRYPOINT ["java", \
  "-javaagent:/app/pyroscope.jar", \
  "-Dpyroscope.server.address=${PYROSCOPE_SERVER_ADDRESS:http://pyroscope:4040}", \
  "-Dpyroscope.application.name=${PYROSCOPE_APPLICATION_NAME:scarlet-auth}", \
  "-Dpyroscope.format=jfr", \
  "-Dpyroscope.profiler.event=cpu", \
  "-Dpyroscope.profiler.alloc=512k", \
  "-jar", "app.jar"]
