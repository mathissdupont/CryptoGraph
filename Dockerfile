FROM gradle:8.12-jdk17 AS fraunhofer-exporter-builder

WORKDIR /workspace/tools/fraunhofer-exporter
COPY tools/fraunhofer-exporter/settings.gradle.kts ./
COPY tools/fraunhofer-exporter/build.gradle.kts ./
COPY tools/fraunhofer-exporter/src ./src
RUN gradle --no-daemon shadowJar

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CRYPTOGRAPH_FRAUNHOFER_EXPORTER=/opt/cryptograph/fraunhofer-exporter.jar
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV LD_LIBRARY_PATH=/usr/local/lib/python3.12/site-packages/jep
ENV CPG_JEP_LIBRARY=/usr/local/lib/python3.12/site-packages/jep/libjep.so

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt pyproject.toml README.md ./
COPY src ./src
COPY config ./config
COPY samples ./samples
COPY docs ./docs
COPY tools ./tools
COPY tests ./tests
COPY --from=fraunhofer-exporter-builder /workspace/tools/fraunhofer-exporter/build/libs/fraunhofer-exporter.jar /opt/cryptograph/fraunhofer-exporter.jar

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -e .

ENTRYPOINT ["cryptograph"]
CMD ["scan", "--input", "samples", "--output", "output/result.json"]
