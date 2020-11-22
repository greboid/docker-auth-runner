FROM registry.greboid.com/mirror/cesanta/docker_auth:1 as cessanta

FROM registry.greboid.com/mirror/golang:latest as configbuilder
WORKDIR /app
COPY . /app
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -trimpath -ldflags=-buildid= -o generator .

FROM gcr.io/distroless/base-debian10
WORKDIR /app
COPY --from=configbuilder /app/generator /app/generator
COPY --from=cessanta /docker_auth/auth_server /app/auth_server
ENTRYPOINT ["/app/generator"]
