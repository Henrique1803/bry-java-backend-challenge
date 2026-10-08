# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Estágio 1 (build): compila e testa a aplicação em um ambiente padronizado
# JDK 17 + Maven Wrapper
# ---------------------------------------------------------------------------
FROM eclipse-temurin:17-jdk-noble AS build

WORKDIR /workspace

# Copia apenas o necessário para resolver as dependências. Esta camada fica em
# cache e só é refeita quando o pom.xml ou o wrapper mudarem.
COPY mvnw pom.xml ./
COPY .mvn/ .mvn/
RUN ./mvnw -B -q dependency:go-offline

COPY src/ src/
COPY resources/ resources/

# Os testes rodam por padrão. --build-arg SKIP_TESTS=true para um build rápido.
ARG SKIP_TESTS=false
RUN ./mvnw -B package -DskipTests=${SKIP_TESTS} \
    && cp target/bry-java-backend-challenge-*.jar /workspace/app.jar

# ---------------------------------------------------------------------------
# Estágio 2 (runtime): imagem enxuta, apenas com JRE, o jar e os recursos do
# desafio, executando com um usuário sem privilégios.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:17-jre-noble AS runtime

RUN groupadd --system app \
    && useradd --system --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=build /workspace/app.jar app.jar
COPY resources/ resources/
RUN mkdir artifacts && chown app:app artifacts

USER app

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
    CMD curl -fsS http://localhost:8080/actuator/health || exit 1

# Argumentos extras são repassados para a aplicação, por exemplo:
#   docker run bry-java-backend-challenge:local --spring.profiles.active=cli
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
