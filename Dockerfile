FROM golang AS build
WORKDIR /app
COPY . .
RUN mkdir -p build
ENV GOPROXY=https://goproxy.cn,https://goproxy.io,direct
RUN go build -ldflags="-s -w -linkmode external -extldflags -static" -tags netgo -o build/authzd ./cmd/authzd

FROM scratch
WORKDIR /
COPY --from=build /app/build/authzd .
ENTRYPOINT ["/authzd"]