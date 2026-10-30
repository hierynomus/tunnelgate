# Static musl binaries are built outside Docker (`mise run build-musl`) and copied in, so the
# image has no build stage and needs no emulation for arm64. The base is pinned by digest
# (multi-arch index); Dependabot proposes updates.
FROM registry.suse.com/bci/bci-minimal:16.0@sha256:f3098db074921072ceab39662b5f655b7d90b919a4a5b0fee5b15c499192cd5e
ARG TARGETARCH
COPY --chmod=0755 target/image/${TARGETARCH}/tunnelgate-operator /usr/local/bin/tunnelgate-operator
COPY --chmod=0755 target/image/${TARGETARCH}/tunnelgate /usr/local/bin/tunnelgate
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tunnelgate-operator"]
