// Package imagespec holds the OCI image-spec v1.1.1 media types and structs,
// plus the Docker distribution equivalents hull must interoperate with.
//
// The types here are wire types: they are the exact JSON shape a registry
// serves. Nothing in this package does I/O; conversion into hull's own domain
// model lives in ToTypesConfig.
package imagespec

// OCI image-spec v1.1.1 media types.
const (
	// MediaTypeImageIndex is a multi-platform image index (manifest list).
	MediaTypeImageIndex = "application/vnd.oci.image.index.v1+json"
	// MediaTypeImageManifest is a single-platform image manifest.
	MediaTypeImageManifest = "application/vnd.oci.image.manifest.v1+json"
	// MediaTypeImageConfig is the image configuration blob.
	MediaTypeImageConfig = "application/vnd.oci.image.config.v1+json"
	// MediaTypeImageLayer is an uncompressed tar layer.
	MediaTypeImageLayer = "application/vnd.oci.image.layer.v1.tar"
	// MediaTypeImageLayerGzip is a gzip-compressed tar layer.
	MediaTypeImageLayerGzip = "application/vnd.oci.image.layer.v1.tar+gzip"
	// MediaTypeImageLayerZstd is a zstd-compressed tar layer.
	MediaTypeImageLayerZstd = "application/vnd.oci.image.layer.v1.tar+zstd"
	// MediaTypeImageLayerNonDistributable is the deprecated OCI foreign layer type.
	MediaTypeImageLayerNonDistributable = "application/vnd.oci.image.layer.nondistributable.v1.tar"
	// MediaTypeImageLayerNonDistributableGzip is the deprecated OCI foreign gzip layer type.
	MediaTypeImageLayerNonDistributableGzip = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
	// MediaTypeEmptyJSON is the "{}" descriptor used for config-less artifacts.
	MediaTypeEmptyJSON = "application/vnd.oci.empty.v1+json"
)

// Docker distribution media types.
const (
	// MediaTypeDockerManifestList is the Docker schema 2 manifest list.
	MediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	// MediaTypeDockerManifest is the Docker schema 2 manifest.
	MediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	// MediaTypeDockerConfig is the Docker image config blob.
	MediaTypeDockerConfig = "application/vnd.docker.container.image.v1+json"
	// MediaTypeDockerLayerGzip is the Docker gzip-compressed layer.
	MediaTypeDockerLayerGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	// MediaTypeDockerLayer is the Docker uncompressed layer (rare, used by some builders).
	MediaTypeDockerLayer = "application/vnd.docker.image.rootfs.diff.tar"
	// MediaTypeDockerForeignLayer is a non-distributable ("foreign") Docker layer,
	// which must be fetched from the descriptor URLs rather than the registry.
	MediaTypeDockerForeignLayer = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
	// MediaTypeDockerManifestSchema1 is the obsolete unsigned schema 1 manifest.
	MediaTypeDockerManifestSchema1 = "application/vnd.docker.distribution.manifest.v1+json"
	// MediaTypeDockerManifestSchema1Signed is the obsolete JWS-signed schema 1 manifest.
	MediaTypeDockerManifestSchema1Signed = "application/vnd.docker.distribution.manifest.v1+prettyjws"
)

// EmptyJSONDescriptorDigest is the digest of the two-byte blob "{}", which the
// OCI spec mandates for MediaTypeEmptyJSON descriptors.
const EmptyJSONDescriptorDigest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

// RootFSTypeLayers is the only rootfs.type OCI defines.
const RootFSTypeLayers = "layers"

// IsManifestList reports whether mediaType names a multi-platform index.
func IsManifestList(mediaType string) bool {
	switch mediaType {
	case MediaTypeImageIndex, MediaTypeDockerManifestList:
		return true
	}
	return false
}

// IsManifest reports whether mediaType names a single-platform image manifest.
func IsManifest(mediaType string) bool {
	switch mediaType {
	case MediaTypeImageManifest, MediaTypeDockerManifest:
		return true
	}
	return false
}

// IsLayer reports whether mediaType names any rootfs layer blob, compressed or not.
func IsLayer(mediaType string) bool {
	switch mediaType {
	case MediaTypeImageLayer,
		MediaTypeImageLayerGzip,
		MediaTypeImageLayerZstd,
		MediaTypeImageLayerNonDistributable,
		MediaTypeImageLayerNonDistributableGzip,
		MediaTypeDockerLayer,
		MediaTypeDockerLayerGzip,
		MediaTypeDockerForeignLayer:
		return true
	}
	return false
}

// IsCompressedLayer reports whether mediaType names a layer whose blob must be
// decompressed before the tar stream can be applied.
func IsCompressedLayer(mediaType string) bool {
	switch mediaType {
	case MediaTypeImageLayerGzip,
		MediaTypeImageLayerZstd,
		MediaTypeImageLayerNonDistributableGzip,
		MediaTypeDockerLayerGzip,
		MediaTypeDockerForeignLayer:
		return true
	}
	return false
}

// IsForeignLayer reports whether mediaType names a non-distributable layer that
// a registry will not serve; the descriptor's URLs must be used instead.
func IsForeignLayer(mediaType string) bool {
	switch mediaType {
	case MediaTypeDockerForeignLayer,
		MediaTypeImageLayerNonDistributable,
		MediaTypeImageLayerNonDistributableGzip:
		return true
	}
	return false
}

// IsConfig reports whether mediaType names an image config blob.
func IsConfig(mediaType string) bool {
	switch mediaType {
	case MediaTypeImageConfig, MediaTypeDockerConfig:
		return true
	}
	return false
}

// IsSchema1 reports whether mediaType names an obsolete Docker schema 1
// manifest. hull never parses these; the puller rejects them with a message
// telling the user to ask the registry for a schema 2 or OCI manifest.
func IsSchema1(mediaType string) bool {
	switch mediaType {
	case MediaTypeDockerManifestSchema1, MediaTypeDockerManifestSchema1Signed:
		return true
	}
	return false
}

// AllManifestAccept returns the comma-joined Accept header value a puller sends
// when requesting a manifest, in hull's order of preference: OCI index, OCI
// manifest, Docker manifest list, Docker manifest.
func AllManifestAccept() string {
	return MediaTypeImageIndex + "," +
		MediaTypeImageManifest + "," +
		MediaTypeDockerManifestList + "," +
		MediaTypeDockerManifest
}
