ROM openjdk:8-jdk-alpine
ARG BUILD_VERSION
ARG PROJECT_NAME

ADD ${PROJECT_NAME}-${BUILD_VERSION}.jar spring-boot-webapp.jar

EXPOSE 8082

ENTRYPOINT exec java $JAVA_OPTS -Ddb.host=$DB_HOST -Ddb.port=$DB_PORT -jar /spring-boot-webapp.jar