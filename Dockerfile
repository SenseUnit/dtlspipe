FROM golang AS build

ARG GIT_DESC=undefined

WORKDIR /go/src/github.com/Snawoot/dtlspipe
COPY . .
RUN CGO_ENABLED=0 go build -a -tags netgo -ldflags '-s -w -extldflags "-static" -X main.version='"$GIT_DESC" ./cmd/dtlspipe

FROM scratch
COPY --from=build /go/src/github.com/Snawoot/dtlspipe/dtlspipe /
USER 9999:9999
ENTRYPOINT ["/dtlspipe"]
