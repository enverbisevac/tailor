ARG JAVA_BASE=eclipse-temurin:21-jdk-noble
FROM ${JAVA_BASE} AS build
RUN apt-get update \
    && apt-get install --yes --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY tests/compatibility/java/NativeHealth.java tests/compatibility/java/health.c ./
RUN mkdir /out \
    && javac --release 21 -d /out NativeHealth.java \
    && jar --create --file /out/application.jar --main-class NativeHealth -C /out NativeHealth.class \
    && gcc -shared -fPIC -Wl,-z,noexecstack \
        -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/linux" \
        health.c -o /out/libhealth.so
